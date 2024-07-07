
rule Trojan_Win32_Ninunarch_R{
	meta:
		description = "Trojan:Win32/Ninunarch.R,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {33 c9 89 4d ec 8d 45 ec 50 ff 46 1c e8 90 01 04 ba 90 01 04 ff d2 8d 55 ec a1 90 01 04 83 c4 08 8b 00 8b 12 e8 90 00 } //1
		$a_01_1 = {89 3b 8b 08 ff 51 6c 8b fe 89 7d f4 85 ff 74 1e 8b 07 89 45 f8 66 c7 45 e0 2c 00 ba 03 00 00 00 8b 45 f4 8b 08 ff 51 fc 66 c7 45 e0 20 00 8b 55 d0 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}