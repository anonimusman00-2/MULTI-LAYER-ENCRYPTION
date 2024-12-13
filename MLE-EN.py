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

# Set window title  
if os.name == 'nt':  # for Windows  
    os.system('title Multi Layer Encryption')  
else:  # for other systems  
    print("\033]0;Multi Layer Encryption\007")

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
                raise ValueError(f"{component_name} size must {expected_size} bytes")  
            return decoded  
        except Exception as e:  
            raise ValueError(f"Error validation {component_name}: {str(e)}")  

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
            raise ValueError(f"Error generating layer key: {str(e)}")  

    def _compute_checksum(self, data, salt, master_key):  
        try:  
            h = hmac.new(master_key, salt + data, hashlib.sha512)  
            return h.digest()  
        except Exception as e:  
            raise ValueError(f"Error computing checksum: {str(e)}")  

    def _generate_composite_key(self, master_key, salt, data):  
        try:  
            composite = hashlib.sha512(master_key + salt + data).digest()  
            return composite  
        except Exception as e:  
            raise ValueError(f"Error generating composite key: {str(e)}")

    def _encrypt_aesgcm(self, data, key, iv):  
        try:  
            aesgcm = AESGCM(key)  
            encrypted = aesgcm.encrypt(iv, data, None)  
            return encrypted  
        except Exception as e:  
            raise ValueError(f"AESGCM encryption error: {str(e)}")  

    def _decrypt_aesgcm(self, data, key, iv):  
        try:  
            aesgcm = AESGCM(key)  
            decrypted = aesgcm.decrypt(iv, data, None)  
            return decrypted  
        except Exception as e:  
            raise ValueError(f"AESGCM decryption error: {str(e)}")  

    def _encrypt_chacha(self, data, key, iv):  
        try:  
            chacha = ChaCha20Poly1305(key)  
            encrypted = chacha.encrypt(iv, data, None)  
            return encrypted  
        except Exception as e:  
            raise ValueError(f"ChaCha20Poly1305 encryption error: {str(e)}")  

    def _decrypt_chacha(self, data, key, iv):  
        try:  
            chacha = ChaCha20Poly1305(key)  
            decrypted = chacha.decrypt(iv, data, None)  
            return decrypted  
        except Exception as e:  
            raise ValueError(f"ChaCha20Poly1305 decryption error: {str(e)}")  

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
            raise ValueError(f"AES-CTR encryption error: {str(e)}")  

    def _decrypt_aesctr(self, data, key, iv):  
        try:  
            # Separate MAC and encrypted data  
            mac = data[:64]  # SHA-512 produces 64 bytes  
            encrypted = data[64:]  
            
            # Verify integrity  
            computed_mac = hmac.new(key, encrypted, hashlib.sha512).digest()  
            if not hmac.compare_digest(mac, computed_mac):  
                raise ValueError("MAC verification failed")  
            
            cipher = Cipher(  
                algorithms.AES(key),  
                modes.CTR(iv),  
                backend=default_backend()  
            )  
            decryptor = cipher.decryptor()  
            return decryptor.update(encrypted) + decryptor.finalize()  
        except Exception as e:  
            raise ValueError(f"AES-CTR decryption error: {str(e)}")  

    def _get_layer_algorithm(self, layer_num):  
        """Get encryption algorithm for specific layer"""  
        idx = (layer_num - 1) % len(self.LAYER_ALGORITHMS)  
        return self.LAYER_ALGORITHMS[idx]

    def encrypt(self, message, master_key):  
        try:  
            print("\n" + "="*50)  
            print("PROCESS MULTI LAYER ENCRYPTION")  
            print("="*50)  

            # Validasi input  
            if not isinstance(message, str):  
                raise ValueError("Message must be a string")  
            if not isinstance(master_key, bytes) or len(master_key) != self.KEY_SIZE:  
                raise ValueError(f"Master key must be {self.KEY_SIZE} bytes")  

            start_time = time.time()  
  
            try:  
                data = message.encode('utf-8')  
                pre_hash = hashlib.sha256(data).digest()  
                padder = padding.PKCS7(128).padder()  
                padded_data = padder.update(data) + padder.finalize()  
                layer_data = pre_hash + padded_data  
            except Exception as e:  
                raise ValueError(f"Pre-processing error: {str(e)}")  

            # Generate salt  
            salt = secrets.token_bytes(self.SALT_SIZE)  

            # Generate IV for every layer  
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
                raise ValueError(f"Pre-processing error: {str(e)}")  

            # Encryption process per layer
            for i in range(self.NUM_LAYERS):  
                current_layer = i + 1  
                print(f"\nLayer {current_layer}/{self.NUM_LAYERS}")  
                
                layer_key = self._generate_layer_key(master_key, salt, i)  
                for _ in range(3):  
                    layer_key = hashlib.sha512(layer_key).digest()[:32]  

                try:  
                    algorithm_name, encrypt_func, _, _ = self.LAYER_ALGORITHMS[i % len(self.LAYER_ALGORITHMS)]  
                    print(f"Using {algorithm_name}")  
                    
                    layer_data = encrypt_func(layer_data, layer_key, ivs[i])  
                    
                    if i < self.NUM_LAYERS - 1:  
                        mix_key = hashlib.sha256(layer_key + ivs[i]).digest()  
                        layer_data = bytes(a ^ b for a, b in zip(  
                            layer_data,  
                            mix_key * (len(layer_data) // 32 + 1)  
                        ))  

                    if self.debug:  
                        print(f"\nLayer {current_layer} encryption result:")  
                        print(f"Size: {len(layer_data)} bytes")  
                        print(f"First 32 bytes: {layer_data[:32].hex()}")  

                except Exception as e:  
                    raise ValueError(f"Layer {current_layer} encryption failed: {str(e)}")  

                print(f"✓ Layer {current_layer} completed successfully")  

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

            print("\nSTATISTIC ENCRYPTION:")  
            print("-"*50)  
            print(f"Initial size: {len(message)} bytes")  
            print(f"Outcome measures: {len(layer_data)} bytes")  
            print(f"Processing time: {time.time() - start_time:.2f} detik")  
            print("-"*50)  

            return result  

        except Exception as e:  
            print(f"\nError encryption: {str(e)}")  
            if self.debug:  
                import traceback  
                traceback.print_exc()  
            return None  

    def decrypt(self, encrypted_data, master_key, recovery_mode=False):  
        try:  
            print("\n" + "="*50)  
            print("PROCESS MULTI LAYER DECRYPTION")  
            print("="*50)  

            start_time = time.time()  

            if not isinstance(encrypted_data, dict):  
                raise ValueError("Encrypted data must be in dictionary format")  
            if not isinstance(master_key, bytes) or len(master_key) != self.KEY_SIZE:  
                raise ValueError(f"Master key must be {self.KEY_SIZE} bytes")  

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
                raise ValueError(f"Error decoding components: {str(e)}")  

            if not recovery_mode:  
                checksum = self._compute_checksum(data, salt, master_key)  
                if not hmac.compare_digest(checksum, stored_checksum):  
                    raise ValueError("Checksum verification failed")  

                composite = self._generate_composite_key(master_key, salt, data)  
                if not hmac.compare_digest(composite, stored_composite):  
                    raise ValueError("Composite key verification failed")  

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
                        print(f"\nLayer {current_layer} decryption result:")  
                        print(f"Size: {len(layer_data)} bytes")  
                        print(f"First 32 bytes: {layer_data[:32].hex()}")  

                except Exception as e:  
                    if recovery_mode:  
                        print(f"Warning: Layer {current_layer} decryption failed: {str(e)}")  
                        continue  
                    else:  
                        raise ValueError(f"Layer {current_layer} decryption failed: {str(e)}")  

                print(f"✓ Layer {current_layer} completed successfully")  

            try:   
                stored_hash = layer_data[:32]  
                padded_data = layer_data[32:]  

                unpadder = padding.PKCS7(128).unpadder()  
                data = unpadder.update(padded_data) + unpadder.finalize()  

                if not recovery_mode:  
                    computed_hash = hashlib.sha256(data).digest()  
                    if not hmac.compare_digest(computed_hash, stored_hash):  
                        raise ValueError("Data integrity check failed")  

                message = data.decode('utf-8')  

            except Exception as e:  
                raise ValueError(f"Post-processing error: {str(e)}")  

            print("\nSTATISTIC DECRYPTION:")  
            print("-"*50)  
            print(f"Input size: {len(encrypted_data['data'])} bytes")  
            print(f"Outcome measures: {len(message)} bytes")  
            print(f"Processing time: {time.time() - start_time:.2f} detik")  
            print("-"*50)  

            return message  

        except Exception as e:  
            print(f"\nError decryption: {str(e)}")  
            if self.debug:  
                import traceback  
                traceback.print_exc()  
            return None

def clear_screen():  
    os.system('cls' if os.name == 'nt' else 'clear')  

def print_banner():  
    print("\n" + "="*50)  
    print("CUSTOM MULTI LAYER ENCRYPTION")  
    print("="*50)  

def print_menu():  
    print("\n1. Generate New Master Key")  
    print("2. Manually Input Master Key")  
    print("3. Load Master Key from File")  
    print("4. Encrypt Message")  
    print("5. Decrypt Message")  
    print("6. Decrypt in Recovery Mode")  
    print("7. Show Current Master Key")  
    print("8. System Configuration")  
    print("9. Toggle Debug Mode")  
    print("10. Exit")  
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
        print(f"\nMaster key successfully saved to '{filename}'")  
        return True  
    except Exception as e:  
        print(f"\nError saving master key: {str(e)}")  
        return False  

def load_master_key(filename):  
    try:  
        with open(filename, 'rb') as f:  
            key = f.read()  
        if len(key) != 32:  
            raise ValueError("Invalid key size")  
        return key  
    except Exception as e:  
        print(f"\nError reading master key: {str(e)}")  
        return None  

def save_encrypted_data(data, filename):  
    try:  
        with open(filename, 'w') as f:  
            json.dump(data, f, indent=2)  
        print(f"\nEncrypted data successfully saved to '{filename}'")  
        return True  
    except Exception as e:  
        print(f"\nError saving data: {str(e)}")  
        return False  

def load_encrypted_data(filename):  
    try:  
        with open(filename) as f:  
            return json.load(f)  
    except Exception as e:  
        print(f"\nError reading file: {str(e)}")  
        return None  

def configure_system():  
    print("\nENCRYPTION SYSTEM CONFIGURATION")  
    print("="*30)  
    
    while True:  
        try:  
            num_layers = int(input("\nNumber of encryption layers (min 1): "))  
            if num_layers < 1:  
                print("Number of layers must be at least 1!")  
                continue  
            
            iterations = int(input("Number of PBKDF2 iterations (min 50000): "))  
            if iterations < 50000:  
                print("Iterations must be at least 50000 for security!")  
                continue  
            
            print(f"\nNew Configuration:")  
            print(f"Encryption Layers: {num_layers}")  
            print(f"PBKDF2 Iterations: {iterations}")  
            
            confirm = input("\nApply these settings? (y/n): ").lower()  
            if confirm == 'y':  
                return num_layers, iterations  
            else:  
                return None, None  
            
        except ValueError:  
            print("Input must be a number!")  
            continue  

def main():  
    # Initialize with debug mode off by default  
    crypto = SecureEncryption(debug=False)  
    master_key = None  
    
    while True:  
        clear_screen()  
        print_banner()  
        print(f"\nCurrent Configuration:")  
        print(f"Encryption Layers: {crypto.NUM_LAYERS}")  
        print(f"PBKDF2 Iterations: {crypto.ITERATIONS}")  
        print(f"Debug Mode      : {'ON' if crypto.debug else 'OFF'}")  
        print(f"Master Key      : {'SET' if master_key else 'NOT SET'}")  
        
        print_menu()  
        choice = input("\nSelect an option: ")  

        # [Rest of the main function remains the same as in the original code]  
        # Only text prompts and messages are translated  

        if choice == '1':  
            master_key = generate_master_key()  
            print("\nNew master key generated!")  
            print(f"Key (hex): {master_key.hex()}")  
            
            save = input("\nSave to file? (y/n): ").lower()  
            if save == 'y':  
                filename = input("Filename: ")  
                save_master_key(master_key, filename)  

        elif choice == '2':  
            print("\nEnter master key in hexadecimal format (64 characters):")  
            hex_key = input().strip()  
            
            if is_valid_hex(hex_key):  
                master_key = bytes.fromhex(hex_key)  
                print("Master key set successfully!")  
            else:  
                print("Invalid key format!")

        elif choice == '3':  
            filename = input("\nMaster key filename: ")  
            loaded_key = load_master_key(filename)  
            if loaded_key:  
                master_key = loaded_key  
                print("Master key successfully loaded!")  

        elif choice == '4':  
            if not master_key:  
                print("\nMaster key not set!")  
                input("\nPress Enter to continue...")  
                continue  

            print("\nENCRYPT MESSAGE")  
            print("="*30)  
            print("\nEnter message (press Enter 5 times in a row to finish):")  
            
            # Reading message with multiple lines  
            message_lines = []  
            empty_count = 0  
            
            while empty_count < 4:  
                line = input()  
                if not line:  # If line is empty  
                    empty_count += 1  
                    if empty_count < 4:  # Add empty line except for last 5 enters  
                        message_lines.append("")  
                else:  
                    empty_count = 0  
                    message_lines.append(line)  
            
            # Combine lines with newline  
            message = '\n'.join(message_lines)  
            
            if not message.strip():  
                print("\nMessage is empty!")  
                input("\nPress Enter to continue...")  
                continue  
            
            print("\nProcessing encryption...")  
            encrypted = crypto.encrypt(message, master_key)  
            if encrypted:  
                filename = input("\nOutput filename: ")  
                save_encrypted_data(encrypted, filename)  
            
            input("\nPress Enter to continue...")  

        elif choice == '5' or choice == '6':  
            if not master_key:  
                print("\nMaster key not set!")  
                input("\nPress Enter to continue...")  
                continue  

            recovery_mode = (choice == '6')  
            print(f"\nDECRYPT MESSAGE {'(RECOVERY MODE)' if recovery_mode else ''}")  
            print("="*30)  
            
            filename = input("\nEncrypted filename: ")  
            encrypted_data = load_encrypted_data(filename)  
            
            if encrypted_data:  
                decrypted = crypto.decrypt(encrypted_data, master_key, recovery_mode)  
                if decrypted:  
                    print("\nDecryption result:")  
                    print("-"*30)  
                    print(decrypted)  
                    print("-"*30)  
                    
                    # Add option to save decryption result  
                    save = input("\nSave decryption result to file? (y/n): ").lower()  
                    if save == 'y':  
                        output_filename = input("Enter output filename: ")  
                        try:  
                            with open(output_filename, 'w', encoding='utf-8') as f:  
                                f.write(decrypted)  
                            print(f"\nDecryption result successfully saved to '{output_filename}'")  
                        except Exception as e:  
                            print(f"\nError saving file: {str(e)}")  
            
            input("\nPress Enter to continue...")   

        elif choice == '7':  
            if master_key:  
                print("\nCurrent Master Key:")  
                print(f"Hex: {master_key.hex()}")  
                print(f"Bytes: {master_key}")  
                print(f"Length: {len(master_key)} bytes")  
            else:  
                print("\nMaster key not set!")  
            
            input("\nPress Enter to continue...")  

        elif choice == '8':  
            new_layers, new_iterations = configure_system()  
            if new_layers and new_iterations:  
                crypto.NUM_LAYERS = new_layers  
                crypto.ITERATIONS = new_iterations  
                print("\nSystem configuration successfully updated!")  
                input("\nPress Enter to continue...")  

        elif choice == '9':  
            crypto.debug = not crypto.debug  
            print(f"\nDebug mode {'ON' if crypto.debug else 'OFF'}")  
            input("\nPress Enter to continue...")  

        elif choice == '10':  
            print("\nThank you for using this program!")  
            break  

        else:  
            print("\nInvalid option!")  
            input("\nPress Enter to continue...")  

if __name__ == "__main__":  
    try:  
        main()  
    except KeyboardInterrupt:  
        print("\n\nProgram stopped by user.")  
    except Exception as e:  
        print(f"\nUnexpected error: {str(e)}")  
        if input("\nShow error details? (y/n): ").lower() == 'y':  
            import traceback  
            traceback.print_exc()