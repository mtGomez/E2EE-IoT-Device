import ast
import hashlib
import os
import paho.mqtt.client as mqtt # https://pypi.org/project/paho-mqtt/
import time
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.serialization import load_pem_parameters
import hmac
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import uuid
import ast
from cryptography.hazmat.primitives.asymmetric import dh, padding
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.hazmat.primitives.serialization import PublicFormat
from cryptography.hazmat.primitives.serialization import load_pem_public_key
# Variables
myID = str(uuid.uuid1()) # Identificador del dispositivo IoT
iotMap = dict() # Mapeado de cada identificador de dispositivo IoT junto con su clave secreta compartida

# Clave privada maestra del dispositivo IoT, IMPORTANTE: esta clave debería guardarse de otra forma y no hardcodearla
iotSensor_private_master_key = serialization.load_pem_private_key(
    b'-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDWS4c4IdyVUymV\nn0H/iS/jRpKC0ye5Zf/Ar6WvSUrb5oyIhka01uyjyCc56torj9TSMwMlW6wl0Htq\nFmxFTlNMEn0H5jGZkS5PDB5ihIKUzPNpG1UZGZlkXbKB6Nl0GnDcwVhXTPoUXHzs\netTHr4njv/uA1eg2m9KaZp8W17rGk6CinSOA/97ggPdMhMMNGkJZHdI+qJdx58EO\nQnRY4xQg98YATNRUsuopooEOkzRz8GmwMYZcgLqX2u0BVhMxRNoOGcy2XxIopKDk\n0gvAns/pWL99MeWaKTFiSUH85yS8vr5tv+V4CL327+9NSIG6R++6/lR+7sU8GnLq\nL6yKqTrHAgMBAAECggEAOJnOZ1caSh6jFy/vYK09hsw3GnLnRSLZwG0kV/4F1bs5\nVz4QIue5rTDKm5OaeHMPBU4QAKgL+hjs4AJ4Kn4bpjYj7Bgy9ZrRHnPW+rKBQwg3\nKoXbnjuStl3BLmrwNKhfMw+mY7ijPQmIvXVcCjolM5Cbv1XAddwGbl24m3HzlUsg\ntE6GI/UldCyp0lOAWgw+aXI95hJ58p/fLjw93kLb3oFLzpVf9dM82nlg2zj05tbC\nYszCjvjckSQ0nXAVgVLVuktS7vLfILNLztbgYdbVyRAT6naln/2p/7fw49g27j6n\n3CdCn5FCc5SR48N81K3cEYQ+sWEqCdL+kIlHQa4NQQKBgQD+hnue2gRvBHS+M3Ve\nqA+ZyhQlPjW0UvwHh2YhjKFCxje01w9kMty54y9MQhnkJ2po44gOBcqcBgIwInl/\nRXn8NscfoR3/xRgU20P8McK49wZF3vceSzROCNz3Bist9fG9sGI9aZRdOB+sZLCW\n45SekUx2/oQiRKHmnKVJRNT7EQKBgQDXiV/7Gy0birw+UZCM7HEzFBI7zRDVvDDw\n1isl4/9pogRFGjJeIX5cUk63b+WJ66FJJ4oCHkjdM6DeNeZxaXcsj9ETVML6fvY5\nAlPkTdQjfUDcjKbbNIYtPrb4Dx624XT59E5Dp9HYUWNrz3YKmnB1hhe6z9YaY5+V\n7Dr5IbloVwKBgQCgoCA91Jq9sRM3wWPNs8P8qwHhqwvbXA9/dNxoScavTEZ1ks88\nzbhse0orFwAd8x39SbJgHxmJM2WIGQmR3zeniq5JcLVs52ZWKzYRXxni/snvqFFN\nxeohYQiJwFPZsn+31St6VDn0Rmn+sqCa6M6u70VRRzf+JFAEKFFLFuxN8QKBgCxK\nO2HjLLq7IIGByz1aHMzNNA37zpjNChWDPOyVVFfFhjEY9/6lzUx1UV2abcWQmNzq\ndg6HYJurz0O6ObdWX7nVd7YMNeC5lCkU1F5Wq9/7DggEEwl6WpQTjg+dM8eKvrna\nPPbkFlfoKZDu2afGIpPT0S5/JNTZYeKx31BwYKQTAoGAWYFpKpg/4LpR+s8YWKYi\nr6G9fWUWksIDju84DsDR2PHoagFMq9SQ3d6wC92NTLi7vIqMP9H1Cg1bYBKYEN4k\nHGL19siIM81oLCqaqMVOygp27/hR3Y2WA7C5AFh3sjfuWl5iESl6iYW5czEzh01P\nD62EqZr+HPva8FQqdSgYU0A=\n-----END PRIVATE KEY-----\n',
    password=None)

# Clave publica de la plataforma IoT IMPORTANTE: cada plataforma debería de tener su clave pública
webUI_public_master_key = serialization.load_pem_public_key(
    b'-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA2L/J9cAoSAH5j1/XxSMp\nP/1XxkJJuaIZpLIy+63Mwg2ekgPbYXnxQgCzxHBWn3vhq4CI7/CRXrY1gXiezUir\nKEOonyUEwd91pP010HwEBB7XmggBs8RkdX6mbzPyJzRRcEKVx7ZrVOP3H6dFV47X\nsD8+W5FsT8QdqjFONAGcwtnJnzxXyrDp48diiXrHl35cj4zuz8FLQE3YkoIGkakl\nlSw05P2lQz3fcOlTS2Wjtn7a5R1W2awTb19TbeKdif1XNclQlwylIWEXENIfew3h\nPmYApBiCyfbPyQ4Wrs/3cHKTLYgaKmWmGcNkmQjuNMFmwKaFsczV/SR7IqBeCwHL\nEQIDAQAB\n-----END PUBLIC KEY-----\n')


# Metodo para conectar con el broker mqtt
def on_connect(client, userdata, flags, rc):
    print("Connected with result code "+str(rc))

    #Topics suscriptions
    client.subscribe("UMA/"+myID+"/DH")
    client.subscribe("UMA/" + myID + "/Remove")


# Metodo para gestionar los mensajes recibidos en función de los topics suscritos
def on_message(client, userdata, msg):
    # Topic del mensaje
    topic = msg.topic

    # Payload del mensaje decodificado
    payload = msg.payload.decode("utf-8")

    # Si el topic es "UMA/"+myID+"/DH" entonces comienza la asociacion desde el POV del dispositivo IoT
    if topic == "UMA/"+myID+"/DH":
        # Parsea los bytes recibidos a "Json"
        payload_dict = ast.literal_eval(payload)

        # Verifica la firma para autenticar el mensaje enviado por el dispositivo IoT
        if not verify_message(webUI_public_master_key, payload_dict["HMAC"], payload_dict["data"]):
            return

        # Parsea los bytes recibidos a "Json"
        payload_dict = ast.literal_eval(payload_dict["data"].decode("utf-8"))

        # Si contiene la clave de la plataforma IoT se comienza el pairing
        if "a_public_key_pem" in payload_dict:
            # Deserializa la clave y los parámetros enviados por la plataforma IoT
            dh_params = load_pem_parameters(payload_dict["params_pem"])
            a_pk = load_pem_public_key(payload_dict["a_public_key_pem"])

            if isinstance(dh_params, dh.DHParameters) and isinstance(a_pk, dh.DHPublicKey):
                # Genera su par publico privada
                b_private_key = dh_params.generate_private_key()
                b_public_key = b_private_key.public_key()

                # Calcula la clave compartida
                b_shared_key = b_private_key.exchange(a_pk)

                # Mapea el identificador de la plataforma IoT junto con la clave compartida
                iotMap[payload_dict["id"]] = b_shared_key

                # Serializa la clave publica del dispositivo IoT
                b_public_key_pem = b_public_key.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)

                # Crear un mensaje en formato "Json" con la clave publica y el ID del dispositivo
                data = {'b_public_key_pem': b_public_key_pem, 'id': myID}

                # Pasa el "Json" a formato bytes UTF-8
                data = bytes(str(data), "utf-8")

                # Firma digital con la clave privada del dispositivo IoT
                signature = sign_message(iotSensor_private_master_key, data)

                # Crea un "Json" con el mensaje y la firma sobre el mensaje
                final_data = {'data': data, 'HMAC': signature}

                # Pasa el "Json" a formato bytes UTF-8
                final_data = bytes(str(final_data), "utf-8")

                # Envio del mensaje
                client.publish("UMA/"+myID+"/DH", final_data)

    if topic == "UMA/"+myID+"/Remove":
        # Parsea los bytes recibidos a "Json"
        payload_dict = ast.literal_eval(payload)

        # Clave compartida con la plataforma IoT mapeada despues del pairing y el DH con HMAC
        # Se utilizan 32 bytes ya que la clave compartida mediante DH es de 64 y AES no soporta este tamaño de clave
        decipher_key = iotMap[key][0:32]

        # Crea un hash para autenticar el mensaje (formato IPSEC)
        h = hmac.new(decipher_key,  payload_dict["data"], hashlib.sha256)

        if not h.digest() == payload_dict["HMAC"]:
            return

        # Parsea los bytes recibidos a "Json"
        payload_dict = ast.literal_eval(payload_dict["data"].decode("utf-8"))

        # Eliminar la referencia en el mapa entre el ID de la plataforma IoT y su clave compartida
        iotMap.pop(payload_dict["id"])


# Metodo para firmar un mensaje en función de un key
def sign_message(key, msg):
    signature = key.sign(
        data=msg,
        padding=padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        algorithm=hashes.SHA256()
    )

    return signature


# Metodo para verificar un mensaje
def verify_message(key, signature, msg):
    try:
        key.verify(
            signature,
            msg,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except InvalidSignature:
        # Si la excepcion salta, sale del metodo sin mapear nada ya que el mensaje ha sido modificado
        return False


def cipher_message(cipher_key, plain_text):
    # Vector de inicialización para el modo de cifrado
    iv = os.urandom(32)

    # Crea un objeto cifrador mediante el metodo de operacion ECB
    encryptor_ecb = Cipher(algorithms.AES(cipher_key), modes.ECB()).encryptor()

    # Cifra el texto con el cifrador
    cipher_text = encryptor_ecb.update(plain_text)
    encryptor_ecb.finalize()

    # Crear un mensaje en formato "Json" con el texto cifrado
    data = {'cipher_text': cipher_text}

    return data


def decipher_message():
    pass


client = mqtt.Client() # Crea una instancia del broker mqtt
client.on_connect = on_connect
client.on_message = on_message
client.username_pw_set("public","public") # Usuario y contraseña del broker mqtt
client.connect("public.cloud.shiftr.io", 1883, 60) # URL, puerto, refresh_time del broker mqtt

# Inicia una nueva hebra
client.loop_start()

while 1:
    # Cada segundo publica su identificador para dejar constancia de que está vivo
    client.publish("UMA/IDs", myID)

    # Envia información a cada plataforma IoT con la que se encuentra asociada
    for key in iotMap:
        # Clave compartida con la plataforma IoT mapeada despues del pairing y el DH con HMAC
        # Se utilizan 32 bytes ya que la clave compartida mediante DH es de 64 y AES no soporta este tamaño de clave
        cipher_key = iotMap[key][0:32]

        # Crea aleatoriamente datos (para emular un mensaje) de 16 bytes
        # Para realizar envios de datos que no son multiplos de 128 bytes es necesario realizar padding
        plain_text = os.urandom(16)

        # Cifra el mensaje dada una clave y un mensaje
        data = cipher_message(cipher_key, plain_text)

        # Crea un hash para autenticar el mensaje (formato IPSEC)
        h = hmac.new(cipher_key, data["cipher_text"], hashlib.sha256)

        # Crear un mensaje en formato "Json" con el texto cifrado y el HMAC
        final_data = {'cipher_text': data["cipher_text"], 'HMAC': h.digest()}

        # Pasa el "Json" a formato bytes UTF-8
        final_data = bytes(str(final_data), "utf-8")

        # Publica un nuevo mensaje en el topic "UMA/" + myID + key + "/Data" junto con el HMAC
        client.publish("UMA/" + myID + key + "/Data", final_data)

    time.sleep(3)