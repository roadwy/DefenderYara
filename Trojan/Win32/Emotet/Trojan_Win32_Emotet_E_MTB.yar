
rule Trojan_Win32_Emotet_E_MTB{
	meta:
		description = "Trojan:Win32/Emotet.E!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 06 00 00 "
		
	strings :
		$a_02_0 = {6a 40 68 00 10 00 00 ff 75 0c 56 ff 55 c0 ff 75 0c 8b f8 ff 75 08 57 ff 55 e0 83 c4 0c ff 75 0c 8d 45 0c 50 57 56 53 56 ff 75 f4 ff 55 e4 f7 d8 1b c0 23 c7 5f 5e 5b c9 c3 90 0a ff 00 8d 45 f8 50 56 56 68 03 80 00 00 ff 75 fc ff 55 e8 85 c0 74 } //1
		$a_02_1 = {6a 40 68 00 10 00 00 ff 75 0c 56 ff 55 c0 ff 75 0c 8b f8 ff 75 08 57 ff 55 e0 83 c4 0c 8d 45 0c ff 75 0c 50 57 56 53 56 ff 75 f4 ff 55 e4 f7 d8 1b c0 23 c7 5f 5e 5b c9 c3 90 0a ff 00 8d 45 f8 50 56 56 68 03 80 00 00 ff 75 fc ff 55 e8 85 c0 74 } //1
		$a_00_2 = {6d 00 65 00 6d 00 63 00 70 00 79 00 } //1 memcpy
		$a_00_3 = {56 00 69 00 72 00 74 00 75 00 61 00 6c 00 41 00 6c 00 6c 00 6f 00 63 00 } //1 VirtualAlloc
		$a_00_4 = {43 00 72 00 79 00 70 00 74 00 45 00 6e 00 63 00 72 00 79 00 70 00 74 00 } //1 CryptEncrypt
		$a_00_5 = {43 00 72 00 79 00 70 00 74 00 41 00 63 00 71 00 75 00 69 00 72 00 65 00 43 00 6f 00 6e 00 74 00 65 00 78 00 74 00 57 00 } //1 CryptAcquireContextW
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1) >=5
 
}