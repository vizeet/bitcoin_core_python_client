import random
import time
import hashlib
import binascii
import pygame
import pygame.camera
import sounddevice as sd
import queue
import time

q = queue.Queue()

#def getRandomNumber():
#        return random.SystemRandom().getrandbits(256)

def getRawCameraOutput():
        pygame.init()
        pygame.camera.init()
        cam = pygame.camera.Camera(pygame.camera.list_cameras()[0])
        cam.start()
        raw = cam.get_raw()
        cam.stop()
        pygame.camera.quit()
        return raw

def callback(indata, frames, time, status):
        if status:
                print(status)
        q.put(indata.copy())

def getRawMicOutput():
        duration = 1  # seconds
        out = b''
        rec_start = int(time.time())

        with sd.InputStream(samplerate=48000, channels=2, callback=callback):
                rec_time = int(time.time()) - rec_start
                while rec_time <= duration:
                        rec_time = int(time.time()) - rec_start
                out = q.get()

        print('outdata = %s' % out)
        return out

def get256BitRandomNumber():
        h = hashlib.sha256()

        # update with raw camera output
        raw_photo = getRawCameraOutput()
        h.update(raw_photo)

        # update with raw mic output
        raw_sound = getRawMicOutput()
#        print('raw sound = %s' % bytes.decode(binascii.hexlify(raw_sound)))
        h.update(raw_sound)

        # update with system random number
        sys_rand = '%x' % random.SystemRandom().randint(0, 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff)
        sys_rand_b = binascii.unhexlify(sys_rand)
        h.update(sys_rand_b)

        h_b = h.digest()
        return h_b

if __name__ == '__main__':
        print('random number = %s' % bytes.decode(binascii.hexlify(get256BitRandomNumber())))
