#Jackson Vaughn
def DHKey(p,g,a,b):

    #We need to find Alices and Bobs value
    #Alice and Bobs public keys
    AKey = 0
    BKey = 0

    
    AKey = pow(g,a) % p
    print(f"Calculate: Alices Key = (g^a) % p: {g} ^ {a} % {p}")
    BKey = pow(g,b) % p
    print(f"Calculate: Bobs Key = (g^b) % p: {g} ^ {b} % {p}")

    print(f"Alice key = {AKey}")
    print(f"Bob key = {BKey}")

    SAKey = (BKey ** a) % p
    SBKey = (AKey ** b) % p

    print(f"calculate the shared key with Bobs secret key BKey ^ a % p: {BKey} ^ {a} % {p}")
    print(f"calculate the shared key with Alices secret key AKey ^ b % p: {AKey} ^ {b} % {p}")

    if SAKey == SBKey:
        print(f"the secret key is = {SBKey}")
    else:
        print("error")


    

    #Now we need to get the secrete key

def RSAKey(p,q,e):

    #From the lecture
    #1) Pick large primes p and q.
    #2) Compute n=pq and phi(n)=(p-1)(q-1)
    #3) Pick a value e such that gcd(e, phi(n)) = 1. (Note that this is fairly easy to do by randomly picking
    #values e and testing them with Euclid’s algorithm until you find one that works.)
    #4) Compute d such that ed phi 1 (mod phi(n)). You are guaranteed to be able to do this by the extended Euclidean algorithm

    #Find n
    n = p * q
    print (f"n = {n}")
    #Find phi n
    phi = (p - 1) * (q - 1)
    print(f"phi of n = {phi}")
    d = 0

    
    #brute force method!
    for i in range(2,phi):
        if i * e % phi == 1:
            print(f"{i} * {e} = {i*e % phi}")
            d = i
            exit
    print(f"d = {d}")
    
    
def RSADecrypt(e,n):

    #read in from cipher.txt

    file = open('question3.txt','r')

    ciphertext = [int(line) for line in file]
    #factor n into p and q to find private key d

    #use the a b method   
    #find all prime actors of n
    p = getFactor(n)
    q = n //p

    print(f"p = {p}")
    print(f"q = {q}")
   
   #find phi
    phi = (p - 1) * (q - 1)
    d = modInv(e,phi)
    print(f"d = {d}")


    #now that we have d, we just need to decrpt the message

    blocksize = getBlockSize(n)

    #D = Cipher^d  mod n
    plaintext = ''
    for cipherblock in ciphertext:
        plainblock = fastmodexpo(cipherblock,d,n)
        plaintext += convertBack(plainblock,blocksize)
    print(plaintext)

def convertBack(msg, blocksize):

    res = ""

    # Concatenate letters from back to front.
    for i in range(blocksize):
        let = chr(msg%26 + ord('A'))
        res = let + res
        msg = msg//26

    # Ta da!
    return res
def getBlockSize(n):

    res = 0
    mult = 1

    # If we can multiply 26 into our current size, we can add 1 to our blocksize.
    while 26*mult <= n:
        res += 1
        mult *= 26

    # Here is our result.
    return res

#FUnction copied from professor Guhas RSA.py 
# Returns a list storing [x, y, gcd(a,b)] where ax + by = gcd(a,b).
def EEA(a,b):

    # End of algorithm, 1*a + 0*b = a
    if b == 0:
        return [1,0,a]

    # Recursive case.
    else:

        # Next quotient and remainder.
        q = a//b
        r = a%b

        # Algorithm runs on b, r.
        rec = EEA(b,r)

        # Here is how we put the solution back together!
        return [rec[1], rec[0]-q*rec[1], rec[2]]

#FUnction copied from professor Guhas RSA.py 
# Returns the modular inverse of x mod n. Returns 0 if there is no modular
# inverse.
def modInv(x,n):

    # Call the Extended Euclidean.
    arr = EEA(n, x)

    # Indicates that there is no solution.
    if arr[2] != 1:
        return 0

    # Do the wrap around, if necessary.
    if arr[1] < 0:
        arr[1] += n

    # This is the modular inverse.
    return arr[1]

def fastmodexpo(base,exp,mod):

    # Base case.
    if exp == 0:
        return 1

    # Speed up here with even exponent.
    if exp%2 == 0:
        tmp = fastmodexpo(base,exp//2,mod)
        return (tmp*tmp)%mod

    # Odd case, must just do the regular ways.
    return (base*fastmodexpo(base,exp-1,mod))%mod


def getFactor(n):

    a = 2
    b = 2

    while (True):

        # a steps once, b steps twice in the sequence.
        a = (a*a+1)%n
        b = (b*b+1)%n
        b = (b*b+1)%n

        # Get the difference between a,b.
        diff = a-b
        if diff < 0:
            diff += n

        # Give this a shot!
        factor = gcd(n, diff)

        # Found a factor.
        if factor > 1 and factor < n:
            return factor

        # Test failed.
        elif factor == n:
            return -1

def gcd(a,b):
    if b == 0:
        return a
    return gcd(b, a%b)


def ElGamalDecrypt(q,g,Ya):
    

    with open('question4.txt', 'r') as file:
    # Read all lines, split by spaces, and convert to integers
        ciphertext = [list(map(int, line.split())) for line in file]


    base = 1
    step = 1000000
    exp = 0
    multi = pow(g,step,q)
    dict = {}
    a = 0
    #first step is to find a
    #Ya = g^a mod q
    #used the dictionaly method
    for i in range(0,311):
        base = (base * multi) % q
        exp = exp + step
        dict[base] = exp
    small = 1
    for i in range (0,1000001):
        check = small * Ya
        check = check % q

        if check in dict:
            tmp = dict.get(check)
            tmp = tmp -i
            a = tmp
            break
        small = (small * g) % q
       
    print(f"a = {a}")

    #now that we have a we can start decrypting
    #For each block, calculate C1^a mod q. This gives us the value of K
    #Calculate K-1 mod q.
    #Multiply K-1 by C2 mod q
    #loop through each block and apply the decrypting forumla
    plaintext = ''
    for c1, c2 in ciphertext:

        k = pow(c1,a,q)
        kinv = pow(k,-1,q)

        res = (kinv * c2) % q
        plaintext += recover(res)

        #do a mod inverse
    print(plaintext)

def recover(msg):
    #each block is 6 chars

    base = 26
    res = [''] * 6
    for i in range(5,-1,-1):
        tmp = msg % base
        res[i] = chr(tmp + ord('A'))
        msg //= base

    return ''.join(res)
        

DHKey(67,13,28,51)
#RSAKey(31,23,139)
#RSADecrypt(395065083027011624330977,576025912082114341909169)
#ElGamalDecrypt(310000037,52216224,32298658)