
rule Trojan_Win32_CryptInject_CT_MTB{
	meta:
		description = "Trojan:Win32/CryptInject.CT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_01_0 = {8b 45 dc 8a 00 88 45 eb 0f be 45 eb 89 45 f4 8b 45 ec 31 45 f4 8b 45 f4 88 45 eb 8a 55 eb 8b 45 e0 88 10 ff 45 e0 ff 45 dc ff 45 f0 8b 45 f0 3b 45 0c 0f 9c c0 84 c0 75 c7 } //1
		$a_01_1 = {53 63 61 6e 6e 69 6e 67 20 66 6f 72 20 56 4d 77 61 72 65 } //1 Scanning for VMware
		$a_01_2 = {53 63 61 6e 6e 69 6e 67 20 66 6f 72 20 53 61 6e 64 62 6f 78 69 65 } //1 Scanning for Sandboxie
		$a_01_3 = {56 4d 77 61 72 65 20 64 65 74 65 63 74 65 64 21 } //1 VMware detected!
		$a_01_4 = {53 61 6e 64 62 6f 78 69 65 20 64 65 74 65 63 74 65 64 21 } //1 Sandboxie detected!
		$a_01_5 = {44 65 63 72 79 70 74 69 6e 67 } //1 Decrypting
		$a_01_6 = {55 6e 70 61 63 6b 69 6e 67 20 53 75 63 63 65 73 73 66 75 6c } //1 Unpacking Successful
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}