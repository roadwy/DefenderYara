
rule Trojan_Win32_Zenpak_ASAE_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.ASAE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 03 00 "
		
	strings :
		$a_01_0 = {8b 45 dc 33 45 e0 89 45 e0 8b 45 e0 03 45 e8 89 45 e8 8b 45 e4 05 01 } //03 00 
		$a_01_1 = {8b 4d f4 33 4d ec 89 4d ec 8b 4d ec 03 4d b0 89 4d b0 8b 45 c0 05 01 } //01 00 
		$a_01_2 = {6d 00 6f 00 76 00 65 00 74 00 68 00 67 00 61 00 74 00 68 00 65 00 72 00 65 00 64 00 74 00 45 00 53 00 73 00 61 00 69 00 64 00 79 00 6f 00 75 00 2e 00 72 00 65 00 73 00 6f 00 } //01 00  movethgatheredtESsaidyou.reso
		$a_01_3 = {66 00 61 00 63 00 65 00 74 00 6f 00 2e 00 76 00 6f 00 70 00 65 00 6e 00 67 00 69 00 76 00 65 00 51 00 } //00 00  faceto.vopengiveQ
	condition:
		any of ($a_*)
 
}