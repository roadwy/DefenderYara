
rule Ransom_Win32_Seelcrypt_A{
	meta:
		description = "Ransom:Win32/Seelcrypt.A,SIGNATURE_TYPE_PEHSTR,08 00 08 00 07 00 00 02 00 "
		
	strings :
		$a_01_0 = {40 62 69 74 6d 65 73 73 61 67 65 2e 63 68 } //01 00  @bitmessage.ch
		$a_01_1 = {57 52 49 54 45 20 54 4f 20 54 48 49 53 20 45 2d 4d 41 49 4c 20 41 44 52 45 53 53 3a } //01 00  WRITE TO THIS E-MAIL ADRESS:
		$a_01_2 = {59 6f 75 72 20 63 6f 6d 70 75 74 65 72 20 77 61 73 20 61 74 74 61 63 6b 65 64 20 62 79 20 74 72 6f 6a 61 6e 20 63 61 6c 6c 65 64 20 63 72 79 70 74 6f 6c 6f 63 6b 65 72 2e 20 41 6c 6c 20 79 6f 75 72 20 66 69 6c 65 73 20 61 72 65 20 65 6e 63 72 79 70 74 65 64 20 77 69 74 68 20 63 72 79 70 74 6f 67 72 61 70 68 69 63 61 6c 6c 79 20 73 74 72 6f 6e 67 20 61 6c 67 6f 72 69 74 68 6d 2c 20 61 6e 64 20 77 69 74 68 6f 75 74 20 6f 72 69 67 69 6e 61 6c 20 64 65 63 72 79 70 74 69 6f 6e 20 6b 65 79 20 72 65 63 6f 76 65 72 79 20 69 73 20 69 6d 70 6f 73 73 69 62 6c 65 2e } //01 00  Your computer was attacked by trojan called cryptolocker. All your files are encrypted with cryptographically strong algorithm, and without original decryption key recovery is impossible.
		$a_01_3 = {54 6f 20 67 65 74 20 79 6f 75 72 20 75 6e 69 71 75 65 20 6b 65 79 20 61 6e 64 20 64 65 63 6f 64 65 20 79 6f 75 72 20 66 69 6c 65 73 2c 20 79 6f 75 20 6e 65 65 64 20 74 6f 20 77 72 69 74 65 20 75 73 20 61 74 20 65 6d 61 69 6c 20 77 72 69 74 74 65 6e 20 62 65 6c 6f 77 20 64 75 72 69 6e 67 20 37 32 20 68 6f 75 72 73 2c 20 20 6f 74 68 65 72 77 69 73 65 20 79 6f 75 72 20 66 69 6c 65 73 20 77 69 6c 6c 20 62 65 20 64 65 73 74 72 6f 79 65 64 20 66 6f 72 65 76 65 72 21 } //02 00  To get your unique key and decode your files, you need to write us at email written below during 72 hours,  otherwise your files will be destroyed forever!
		$a_01_4 = {00 64 65 73 6b 31 2e 62 6d 70 00 } //01 00 
		$a_01_5 = {00 63 68 63 70 20 31 32 35 31 20 3e 20 6e 75 6c 20 00 } //03 00  挀捨⁰㈱ㄵ㸠渠汵 
		$a_01_6 = {62 69 6e 3a 63 6f 6d 3a 65 78 65 3a 62 61 74 3a 70 6e 67 3a 62 6d 70 3a 64 61 74 3a 6c 6f 67 3a 69 6e 69 3a 64 6c 6c 3a 73 79 73 3a } //00 00  bin:com:exe:bat:png:bmp:dat:log:ini:dll:sys:
	condition:
		any of ($a_*)
 
}