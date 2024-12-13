import os  
import time  
import json  
import hmac  
import base64  
import secrets  
import hashlib  
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes  
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305  
from cryptography.hazmat.primitives import padding  
from cryptography.hazmat.backends import default_backend  
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC  
from cryptography.hazmat.primitives import hashes  

# إعداد العنوان للنظام  
if os.name == 'nt':  # للويندوز  
    os.system('title التشفير متعدد الطبقات')  
else:  # للنظم الأخرى  
    print("\033]0;التشفير متعدد الطبقات\007")  

class EncryptionDebug:  
    def __init__(self):  
        self.logs = []  
    
    def log(self, message):  
        self.logs.append(message)  
    
    def clear(self):  
        self.logs = []  
    
    def get_logs(self):  
        return "\n".join(self.logs)  

class SecureEncryption:  
    def __init__(self, debug=False):  
        self.SALT_SIZE = 32  
        self.KEY_SIZE = 32  
        self.TAG_SIZE = 16  
        self.debug = debug  
        self.logger = EncryptionDebug()  
        
        # Default values  
        self.NUM_LAYERS = 20  
        self.ITERATIONS = 50000  
 
        self.LAYER_ALGORITHMS = [  
            ("AESGCM", self._encrypt_aesgcm, self._decrypt_aesgcm, 16),  
            ("ChaCha20Poly1305", self._encrypt_chacha, self._decrypt_chacha, 12),  
            ("AES-CTR+SHA512", self._encrypt_aesctr, self._decrypt_aesctr, 16)  
        ]  

    def _validate_base64(self, data, expected_size, component_name):  
        try:  
            decoded = base64.b64decode(data)  
            if len(decoded) != expected_size:  
                raise ValueError(f"{component_name} يجب أن يكون الحجم {expected_size} bytes")  
            return decoded  
        except Exception as e:  
            raise ValueError(f"خطأ في التحقق {component_name}: {str(e)}")  

    def _generate_layer_key(self, master_key, salt, layer_num):  
        try:  
            info = f"layer{layer_num}".encode('utf-8')  
            kdf = PBKDF2HMAC(  
                algorithm=hashes.SHA512(),  
                length=self.KEY_SIZE,  
                salt=salt + info,  
                iterations=self.ITERATIONS,  
                backend=default_backend()  
            )  
            return kdf.derive(master_key)  
        except Exception as e:  
            raise ValueError(f"حدث خطأ أثناء إنشاء مفتاح الطبقة: {str(e)}")  

    def _compute_checksum(self, data, salt, master_key):  
        try:  
            h = hmac.new(master_key, salt + data, hashlib.sha512)  
            return h.digest()  
        except Exception as e:  
            raise ValueError(f"خطأ في حساب المجموع الاختباري: {str(e)}")  

    def _generate_composite_key(self, master_key, salt, data):  
        try:  
            composite = hashlib.sha512(master_key + salt + data).digest()  
            return composite  
        except Exception as e:  
            raise ValueError(f"حدث خطأ أثناء إنشاء مفتاح مركب: {str(e)}")

    def _encrypt_aesgcm(self, data, key, iv):  
        try:  
            aesgcm = AESGCM(key)  
            encrypted = aesgcm.encrypt(iv, data, None)  
            return encrypted  
        except Exception as e:  
            raise ValueError(f"خطأ تشفير AESGCM: {str(e)}")  

    def _decrypt_aesgcm(self, data, key, iv):  
        try:  
            aesgcm = AESGCM(key)  
            decrypted = aesgcm.decrypt(iv, data, None)  
            return decrypted  
        except Exception as e:  
            raise ValueError(f"خطأ فك تشفير AESGCM: {str(e)}")  

    def _encrypt_chacha(self, data, key, iv):  
        try:  
            chacha = ChaCha20Poly1305(key)  
            encrypted = chacha.encrypt(iv, data, None)  
            return encrypted  
        except Exception as e:  
            raise ValueError(f"خطأ تشفير ChaCha20Poly1305: {str(e)}")  

    def _decrypt_chacha(self, data, key, iv):  
        try:  
            chacha = ChaCha20Poly1305(key)  
            decrypted = chacha.decrypt(iv, data, None)  
            return decrypted  
        except Exception as e:  
            raise ValueError(f"خطأ فك تشفير ChaCha20Poly1305: {str(e)}")  

    def _encrypt_aesctr(self, data, key, iv):  
        try:  
            cipher = Cipher(  
                algorithms.AES(key),  
                modes.CTR(iv),  
                backend=default_backend()  
            )  
            encryptor = cipher.encryptor()  
            encrypted = encryptor.update(data) + encryptor.finalize()  
            
            # Add integrity check with SHA-512  
            mac = hmac.new(key, encrypted, hashlib.sha512).digest()  
            return mac + encrypted  
        except Exception as e:  
            raise ValueError(f"خطأ تشفير AES-CTR: {str(e)}")  

    def _decrypt_aesctr(self, data, key, iv):  
        try:  
            # Separate MAC and encrypted data  
            mac = data[:64]  # SHA-512 produces 64 bytes  
            encrypted = data[64:]  
            
            # Verify integrity  
            computed_mac = hmac.new(key, encrypted, hashlib.sha512).digest()  
            if not hmac.compare_digest(mac, computed_mac):  
                raise ValueError("فشل التحقق من عنوان MAC")  
            
            cipher = Cipher(  
                algorithms.AES(key),  
                modes.CTR(iv),  
                backend=default_backend()  
            )  
            decryptor = cipher.decryptor()  
            return decryptor.update(encrypted) + decryptor.finalize()  
        except Exception as e:  
            raise ValueError(f"خطأ فك تشفير AES-CTR: {str(e)}")  

    def _get_layer_algorithm(self, layer_num):  
        """Get encryption algorithm for specific layer"""  
        idx = (layer_num - 1) % len(self.LAYER_ALGORITHMS)  
        return self.LAYER_ALGORITHMS[idx]

    def encrypt(self, message, master_key):  
        try:  
            print("\n" + "="*50)  
            print("عملية إنكريبسي متعددة الطبقات")  
            print("="*50)  

            # Validasi input  
            if not isinstance(message, str):  
                raise ValueError("الرسالة تحتاج إلى سلسلة من الكلمات")  
            if not isinstance(master_key, bytes) or len(master_key) != self.KEY_SIZE:  
                raise ValueError(f"مفتاح رئيسي هارس {self.KEY_SIZE} bytes")  

            start_time = time.time()  
 
            try:  
                # Konversi string ke bytes dengan encoding yang menjaga newline  
                data = message.encode('utf-8')  
                pre_hash = hashlib.sha256(data).digest()  
                padder = padding.PKCS7(128).padder()  
                padded_data = padder.update(data) + padder.finalize()  
                layer_data = pre_hash + padded_data  
            except Exception as e:  
                raise ValueError(f"خطأ المعالجة المسبقة: {str(e)}")  

            # Generate salt  
            salt = secrets.token_bytes(self.SALT_SIZE)  
  
            ivs = []  
            for i in range(self.NUM_LAYERS):  
                algo_idx = i % len(self.LAYER_ALGORITHMS)  
                iv_size = self.LAYER_ALGORITHMS[algo_idx][3]  
                ivs.append(secrets.token_bytes(iv_size))  

            if self.debug:  
                print("\nGenerated components:")  
                print(f"Salt: {salt.hex()}")  
                for i, iv in enumerate(ivs):  
                    print(f"IV {i+1}: {iv.hex()}")  

            # Pre-processing  
            try:  
                data = message.encode('utf-8')  
                pre_hash = hashlib.sha256(data).digest()  
                padder = padding.PKCS7(128).padder()  
                padded_data = padder.update(data) + padder.finalize()  
                layer_data = pre_hash + padded_data  
            except Exception as e:  
                raise ValueError(f"خطأ المعالجة المسبقة: {str(e)}")  

            for i in range(self.NUM_LAYERS):  
                current_layer = i + 1  
                print(f"\nطبقة {current_layer}/{self.NUM_LAYERS}")  
                
                layer_key = self._generate_layer_key(master_key, salt, i)  
                for _ in range(3):  
                    layer_key = hashlib.sha512(layer_key).digest()[:32]  

                try:  
                    algorithm_name, encrypt_func, _, _ = self.LAYER_ALGORITHMS[i % len(self.LAYER_ALGORITHMS)]  
                    print(f"استخدام {algorithm_name}")  
                    
                    layer_data = encrypt_func(layer_data, layer_key, ivs[i])  
                    
                    if i < self.NUM_LAYERS - 1:  
                        mix_key = hashlib.sha256(layer_key + ivs[i]).digest()  
                        layer_data = bytes(a ^ b for a, b in zip(  
                            layer_data,  
                            mix_key * (len(layer_data) // 32 + 1)  
                        ))  

                    if self.debug:  
                        print(f"\nطبقة {current_layer} نتيجة التشفير:")  
                        print(f"مقاس: {len(layer_data)} بايت")  
                        print(f"أول 32 بايت: {layer_data[:32].hex()}")  

                except Exception as e:  
                    raise ValueError(f"طبقة {current_layer} فشل التشفير: {str(e)}")  

                print(f"✓ طبقة {current_layer} اكتمل بنجاح")  

            # Generate checksums dan composite key  
            checksum = self._compute_checksum(layer_data, salt, master_key)  
            composite_key = self._generate_composite_key(master_key, salt, layer_data)  

            result = {  
                'metadata': {  
                    'version': '1.0',  
                    'timestamp': int(time.time())  
                },  
                'salt': base64.b64encode(salt).decode('utf-8'),  
                'ivs': [base64.b64encode(iv).decode('utf-8') for iv in ivs],  
                'data': base64.b64encode(layer_data).decode('utf-8'),  
                'checksum': base64.b64encode(checksum).decode('utf-8'),  
                'composite_key': base64.b64encode(composite_key).decode('utf-8')  
            }  

            print("\nإحصائيات:")  
            print("-"*50)  
            print(f"الحجم الأول: {len(message)} بايت")  
            print(f"حجم النتيجة: {len(layer_data)} بايت")  
            print(f"وقت العمل: {time.time() - start_time:.2f} ثانية")  
            print("-"*50)  

            return result  

        except Exception as e:  
            print(f"\nخطأ في التشفير: {str(e)}")  
            if self.debug:  
                import traceback  
                traceback.print_exc()  
            return None  

    def decrypt(self, encrypted_data, master_key, recovery_mode=False):  
        try:  
            print("\n" + "="*50)  
            print("عملية وصف متعددة الطبقات")  
            print("="*50)  

            start_time = time.time()  

            if not isinstance(encrypted_data, dict):  
                raise ValueError("يجب أن تكون البيانات المشفرة بتنسيق القاموس")  
            if not isinstance(master_key, bytes) or len(master_key) != self.KEY_SIZE:  
                raise ValueError(f"يجب أن يكون المفتاح الرئيسي {self.KEY_SIZE} بايت")  

            try:  
                salt = self._validate_base64(encrypted_data['salt'], self.SALT_SIZE, "Salt")  
                ivs = []  
                for i, iv in enumerate(encrypted_data['ivs']):  
                    algo_idx = i % len(self.LAYER_ALGORITHMS)  
                    expected_size = self.LAYER_ALGORITHMS[algo_idx][3]  
                    ivs.append(self._validate_base64(iv, expected_size, f"IV {i+1}"))  
                data = base64.b64decode(encrypted_data['data'])  
                stored_checksum = base64.b64decode(encrypted_data['checksum'])  
                stored_composite = base64.b64decode(encrypted_data['composite_key'])  
            except Exception as e:  
                raise ValueError(f"خطأ في فك مكونات: {str(e)}")  

            if not recovery_mode:  
                checksum = self._compute_checksum(data, salt, master_key)  
                if not hmac.compare_digest(checksum, stored_checksum):  
                    raise ValueError("فشل التحقق من المجموع الاختباري")  

                composite = self._generate_composite_key(master_key, salt, data)  
                if not hmac.compare_digest(composite, stored_composite):  
                    raise ValueError("فشل التحقق من المفتاح المركب")  

            layer_data = data  
            for i in range(self.NUM_LAYERS - 1, -1, -1):  
                current_layer = i + 1  
                print(f"\nLayer {current_layer}/{self.NUM_LAYERS}")  

                layer_key = self._generate_layer_key(master_key, salt, i)  
                for _ in range(3):  
                    layer_key = hashlib.sha512(layer_key).digest()[:32]  

                try:  
                    if i < self.NUM_LAYERS - 1:  
                        mix_key = hashlib.sha256(layer_key + ivs[i]).digest()  
                        layer_data = bytes(a ^ b for a, b in zip(  
                            layer_data,  
                            mix_key * (len(layer_data) // 32 + 1)  
                        ))  

                    algorithm_name, _, decrypt_func, _ = self.LAYER_ALGORITHMS[i % len(self.LAYER_ALGORITHMS)]  
                    print(f"Using {algorithm_name}")  

                    layer_data = decrypt_func(layer_data, layer_key, ivs[i])  

                    if self.debug:  
                        print(f"\nطبقة {current_layer} نتيجة فك التشفير:")  
                        print(f"مقاس: {len(layer_data)} بايت")  
                        print(f"أول 32 بايت: {layer_data[:32].hex()}")  

                except Exception as e:  
                    if recovery_mode:  
                        print(f"Warning: طبقة {current_layer} فشل فك التشفير: {str(e)}")  
                        continue  
                    else:  
                        raise ValueError(f"طبقة {current_layer} فشل فك التشفير: {str(e)}")  

                print(f"✓ طبقة {current_layer} اكتمل بنجاح")  

            try:  
                # Post-processing dengan menjaga enter  
                stored_hash = layer_data[:32]  
                padded_data = layer_data[32:]  

                unpadder = padding.PKCS7(128).unpadder()  
                data = unpadder.update(padded_data) + unpadder.finalize()  

                if not recovery_mode:  
                    computed_hash = hashlib.sha256(data).digest()  
                    if not hmac.compare_digest(computed_hash, stored_hash):  
                        raise ValueError("فشل التحقق من سلامة البيانات")  

                # Decode bytes ke string dengan menjaga newline  
                message = data.decode('utf-8')  

            except Exception as e:  
                raise ValueError(f"خطأ ما بعد المعالجة: {str(e)}")  

            print("\nSTATISTIK DEKRIPSI:")  
            print("-"*50)  
            print(f"الإدخال المباشر: {len(encrypted_data['data'])} بايت")  
            print(f"مقاييس النتائج: {len(message)} بايت")  
            print(f"وقت المعالجة: {time.time() - start_time:.2f} ثانية")  
            print("-"*50)  

            return message  

        except Exception as e:  
            print(f"\nخطأ في فك التشفير: {str(e)}")  
            if self.debug:  
                import traceback  
                traceback.print_exc()  
            return None

def clear_screen():  
    os.system('cls' if os.name == 'nt' else 'clear')  

def print_banner():  
    print("\n" + "="*50)  
    print("التشفير متعدد الطبقات المخصص")  
    print("="*50)  

def print_menu():  
    print("\n1. إنشاء مفتاح رئيسي جديد")  
    print("2. إدخال مفتاح رئيسي يدويًا")  
    print("3. تحميل المفتاح الرئيسي من ملف")  
    print("4. تشفير رسالة")  
    print("5. فك تشفير رسالة")  
    print("6. فك التشفير في وضع الاسترداد")  
    print("7. عرض المفتاح الرئيسي الحالي")  
    print("8. إعدادات النظام")  
    print("9. تشغيل/إيقاف وضع التصحيح")  
    print("10. خروج")  
    print("\n" + "="*50)  

def generate_master_key():  
    key = secrets.token_bytes(32)  
    return key  

def is_valid_hex(hex_string):  
    try:  
        return len(hex_string) == 64 and all(c in '0123456789abcdefABCDEF' for c in hex_string)  
    except:  
        return False  

def save_master_key(key, filename):  
    try:  
        with open(filename, 'wb') as f:  
            f.write(key)  
        print(f"\nتم حفظ المفتاح الرئيسي بنجاح في '{filename}'")  
        return True  
    except Exception as e:  
        print(f"\nخطأ في حفظ المفتاح الرئيسي: {str(e)}")  
        return False  

def load_master_key(filename):  
    try:  
        with open(filename, 'rb') as f:  
            key = f.read()  
        if len(key) != 32:  
            raise ValueError("حجم المفتاح غير صالح")  
        return key  
    except Exception as e:  
        print(f"\nخطأ في قراءة المفتاح الرئيسي: {str(e)}")  
        return None  

def save_encrypted_data(data, filename):  
    try:  
        with open(filename, 'w') as f:  
            json.dump(data, f, indent=2)  
        print(f"\nتم حفظ البيانات المشفرة بنجاح في '{filename}'")  
        return True  
    except Exception as e:  
        print(f"\nخطأ في حفظ البيانات: {str(e)}")  
        return False  

def load_encrypted_data(filename):  
    try:  
        with open(filename) as f:  
            return json.load(f)  
    except Exception as e:  
        print(f"\nخطأ في قراءة الملف: {str(e)}")  
        return None  

def configure_system():  
    print("\nإعدادات نظام التشفير")  
    print("="*30)  
    
    while True:  
        try:  
            num_layers = int(input("\nعدد طبقات التشفير (الحد الأدنى 1): "))  
            if num_layers < 1:  
                print("يجب أن يكون عدد الطبقات على الأقل 1!")  
                continue  
            
            iterations = int(input("عدد تكرارات PBKDF2 (الحد الأدنى 50000): "))  
            if iterations < 50000:  
                print("يجب أن يكون عدد التكرارات 50000 على الأقل للأمان!")  
                continue  
            
            print(f"\nالإعدادات الجديدة:")  
            print(f"طبقات التشفير: {num_layers}")  
            print(f"تكرارات PBKDF2: {iterations}")  
            
            confirm = input("\nهل تريد تطبيق هذه الإعدادات؟ (نعم/لا): ").lower()  
            if confirm == 'نعم':  
                return num_layers, iterations  
            else:  
                return None, None  
            
        except ValueError:  
            print("يجب أن يكون الإدخال رقمًا!")  
            continue  

def main():  
    # تهيئة مع وضع التصحيح الافتراضي كإيقاف  
    crypto = SecureEncryption(debug=False)  
    master_key = None  
    
    while True:  
        clear_screen()  
        print_banner()  
        print(f"\nالإعدادات الحالية:")  
        print(f"طبقات التشفير : {crypto.NUM_LAYERS}")  
        print(f"تكرارات PBKDF2: {crypto.ITERATIONS}")  
        print(f"وضع التصحيح    : {'مفعل' if crypto.debug else 'متوقف'}")  
        print(f"المفتاح الرئيسي: {'محدد' if master_key else 'غير محدد'}")  
        
        print_menu()  
        choice = input("\nاختر خيارًا: ")  

        if choice == '1':  
            master_key = generate_master_key()  
            print("\nتم إنشاء مفتاح رئيسي جديد!")  
            print(f"المفتاح (سداسي عشري): {master_key.hex()}")  
            
            save = input("\nهل تريد الحفظ في ملف؟ (نعم/لا): ").lower()  
            if save == 'نعم':  
                filename = input("اسم الملف: ")  
                save_master_key(master_key, filename)  

        elif choice == '2':  
            print("\nأدخل المفتاح الرئيسي بتنسيق سداسي عشري (64 حرفًا):")  
            hex_key = input().strip()  
            
            if is_valid_hex(hex_key):  
                master_key = bytes.fromhex(hex_key)  
                print("تم تعيين المفتاح الرئيسي بنجاح!")  
            else:  
                print("تنسيق المفتاح غير صحيح!")  

        elif choice == '3':  
            filename = input("\nاسم ملف المفتاح الرئيسي: ")  
            loaded_key = load_master_key(filename)  
            if loaded_key:  
                master_key = loaded_key  
                print("تم تحميل المفتاح الرئيسي بنجاح!")  

        elif choice == '4':  
            if not master_key:  
                print("\nلم يتم تعيين المفتاح الرئيسي!")  
                input("\nاضغط Enter للمتابعة...")  
                continue  

            print("\nتشفير رسالة")  
            print("="*30)  
            print("\nأدخل الرسالة (اضغط Enter 5 مرات متتالية للانتهاء):")  
            
            # قراءة الرسالة متعددة الأسطر  
            message_lines = []  
            empty_count = 0  
            
            while empty_count < 4:  
                line = input()  
                if not line:  # إذا كان السطر فارغًا  
                    empty_count += 1  
                    if empty_count < 4:  # أضف سطرًا فارغًا باستثناء 5 أسطر أخيرة  
                        message_lines.append("")  
                else:  
                    empty_count = 0  
                    message_lines.append(line)  
            
            # دمج الأسطر بسطر جديد  
            message = '\n'.join(message_lines)  
            
            if not message.strip():  
                print("\nالرسالة فارغة!")  
                input("\nاضغط Enter للمتابعة...")  
                continue  
            
            print("\nجاري معالجة التشفير...")  
            encrypted = crypto.encrypt(message, master_key)  
            if encrypted:  
                filename = input("\naسم ملف الإخراج: ")  
                save_encrypted_data(encrypted, filename)  
            
            input("\nاضغط Enter للمتابعة...")  

        elif choice == '5' or choice == '6':  
            if not master_key:  
                print("\nلم يتم تعيين المفتاح الرئيسي!")  
                input("\nاضغط Enter للمتابعة...")  
                continue  

            recovery_mode = (choice == '6')  
            print(f"\nفك تشفير الرسالة {'(وضع الاسترداد)' if recovery_mode else ''}")  
            print("="*30)  
            
            filename = input("\nاسم الملف المشفر: ")  
            encrypted_data = load_encrypted_data(filename)  
            
            if encrypted_data:  
                decrypted = crypto.decrypt(encrypted_data, master_key, recovery_mode)  
                if decrypted:  
                    print("\nنتيجة فك التشفير:")  
                    print("-"*30)  
                    print(decrypted)  
                    print("-"*30)  
                    
                    # إضافة خيار حفظ نتيجة فك التشفير  
                    save = input("\nهل تريد حفظ نتيجة فك التشفير في ملف؟ (نعم/لا): ").lower()  
                    if save == 'نعم':  
                        output_filename = input("أدخل اسم الملف: ")  
                        try:  
                            with open(output_filename, 'w', encoding='utf-8') as f:  
                                f.write(decrypted)  
                            print(f"\nتم حفظ نتيجة فك التشفير بنجاح في '{output_filename}'")  
                        except Exception as e:  
                            print(f"\nخطأ في حفظ الملف: {str(e)}")  
            
            input("\nاضغط Enter للمتابعة...")   

        elif choice == '7':  
            if master_key:  
                print("\nالمفتاح الرئيسي الحالي:")  
                print(f"سداسي عشري: {master_key.hex()}")  
                print(f"بايت: {master_key}")  
                print(f"الطول: {len(master_key)} بايت")  
            else:  
                print("\nلم يتم تعيين المفتاح الرئيسي!")  
            
            input("\nاضغط Enter للمتابعة...")  

        elif choice == '8':  
            new_layers, new_iterations = configure_system()  
            if new_layers and new_iterations:  
                crypto.NUM_LAYERS = new_layers  
                crypto.ITERATIONS = new_iterations  
                print("\nتم تحديث إعدادات النظام بنجاح!")  
                input("\nاضغط Enter للمتابعة...")  

        elif choice == '9':  
            crypto.debug = not crypto.debug  
            print(f"\nوضع التصحيح {'مفعل' if crypto.debug else 'متوقف'}")  
            input("\nاضغط Enter للمتابعة...")  

        elif choice == '10':  
            print("\nشكرًا لاستخدامك هذا البرنامج!")  
            break  

        else:  
            print("\nخيار غير صالح!")  
            input("\nاضغط Enter للمتابعة...")  

if __name__ == "__main__":  
    try:  
        main()  
    except KeyboardInterrupt:  
        print("\n\nتم إيقاف البرنامج من قبل المستخدم.")  
    except Exception as e:  
        print(f"\nخطأ غير متوقع: {str(e)}")  
        if input("\nهل تريد عرض تفاصيل الخطأ؟ (نعم/لا): ").lower() == 'نعم':  
            import traceback  
            traceback.print_exc()