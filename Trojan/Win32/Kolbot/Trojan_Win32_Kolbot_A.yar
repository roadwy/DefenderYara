
rule Trojan_Win32_Kolbot_A{
	meta:
		description = "Trojan:Win32/Kolbot.A,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 04 00 00 "
		
	strings :
		$a_02_0 = {5c 74 72 6f 6a 5f 62 6f 74 6e 65 74 [0-02] 5c 6b 6f 6c 5c 65 72 72 } //10
		$a_00_1 = {4e 75 6a 5a 6f 56 4e 4d 5a 2b 32 61 43 44 } //1 NujZoVNMZ+2aCD
		$a_00_2 = {76 6d 6f 37 72 39 50 2b 59 4d 79 46 35 79 35 4d 43 4b 6c 67 59 4e 37 59 37 66 56 69 33 36 4c 58 31 6d 65 47 6b 44 } //1 vmo7r9P+YMyF5y5MCKlgYN7Y7fVi36LX1meGkD
		$a_00_3 = {0f b7 fb 8b 55 00 8a 54 3a ff 0f b7 ce c1 e9 08 32 d1 88 54 38 ff 8b 04 24 0f b6 44 38 ff 66 03 f0 66 69 c6 6d ce 66 05 bf 58 8b f0 43 } //10
	condition:
		((#a_02_0  & 1)*10+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*10) >=21
 
}