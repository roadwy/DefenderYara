
rule Trojan_WinNT_Cutwail_A_sys{
	meta:
		description = "Trojan:WinNT/Cutwail.A!sys,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_03_0 = {0f bf 00 3d 93 08 00 00 90 05 03 05 53 54 55 56 57 0f 90 00 } //02 00 
		$a_01_1 = {fa 0f 20 c0 89 45 fc 25 ff ff fe ff 0f 22 c0 } //01 00 
		$a_01_2 = {8b 45 08 8b 75 0c 05 54 01 00 00 8a 10 8a ca 3a 16 75 1f } //01 00 
		$a_01_3 = {b9 86 00 00 00 33 c0 8b fe f3 ab 68 03 01 00 00 ff 75 08 56 } //01 00 
		$a_01_4 = {33 f6 8b 45 08 6a ff 6a ff ff 74 b5 f0 ff 70 04 } //00 00 
	condition:
		any of ($a_*)
 
}