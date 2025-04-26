
rule Trojan_Win32_TurlaCarbonCryptoPP{
	meta:
		description = "Trojan:Win32/TurlaCarbonCryptoPP,SIGNATURE_TYPE_PEHSTR,07 00 07 00 07 00 00 "
		
	strings :
		$a_01_0 = {4e 38 43 72 79 70 74 6f 50 50 31 32 43 41 53 54 31 32 38 5f 49 6e 66 6f 45 } //1 N8CryptoPP12CAST128_InfoE
		$a_01_1 = {25 70 20 6e 6f 74 20 66 6f 75 6e 64 3f 21 3f 21 } //1 %p not found?!?!
		$a_01_2 = {54 25 70 20 25 64 20 56 3d 25 30 58 20 48 3d 25 70 20 25 73 } //1 T%p %d V=%0X H=%p %s
		$a_01_3 = {5b 54 41 53 4b 5d 20 4f 75 74 70 75 74 74 69 6e 67 20 74 6f 20 73 65 6e 64 20 66 69 6c 65 3a } //1 [TASK] Outputting to send file:
		$a_01_4 = {5b 54 41 53 4b 5d 20 43 6f 6d 6d 73 20 6c 69 62 20 61 63 74 69 76 65 2c 20 70 65 72 66 6f 72 6d 69 6e 67 20 74 61 73 6b 69 6e 67 20 63 68 65 63 6b 73 } //1 [TASK] Comms lib active, performing tasking checks
		$a_01_5 = {5b 54 41 53 4b 5d 20 41 74 74 65 6d 70 74 69 6e 67 20 74 6f 20 67 65 74 20 6f 77 6e 65 72 73 68 69 70 20 6f 66 20 6d 75 74 65 78 3a } //1 [TASK] Attempting to get ownership of mutex:
		$a_01_6 = {43 3a 5c 50 72 6f 67 72 61 6d 20 46 69 6c 65 73 5c 57 69 6e 64 6f 77 73 20 4e 54 5c 68 69 73 74 6f 72 79 2e 6a 70 67 } //1 C:\Program Files\Windows NT\history.jpg
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}