
rule TrojanDropper_Win32_Cutwail_gen_H{
	meta:
		description = "TrojanDropper:Win32/Cutwail.gen!H,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_03_0 = {ff 75 0c ff 75 08 ff 15 90 01 04 85 c0 75 04 32 c0 eb 0c 8b 45 fc 3b 45 10 75 d7 b0 00 04 01 90 00 } //1
		$a_01_1 = {ff 75 f8 58 89 45 f0 8b 45 fc 89 45 e8 c7 45 e0 } //1
		$a_03_2 = {8d 45 e0 50 8d 45 cc 50 90 13 55 54 5d 51 83 65 fc 00 eb 09 ff 75 fc 58 40 40 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1) >=2
 
}