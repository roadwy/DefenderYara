
rule Trojan_WinNT_Cutwail_B_sys{
	meta:
		description = "Trojan:WinNT/Cutwail.B!sys,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 02 00 "
		
	strings :
		$a_01_0 = {c6 45 ff 00 c6 45 fe 01 fa 0f 20 c0 89 45 f8 25 ff ff fe ff 0f 22 c0 33 d2 39 55 0c 76 3e 8b 45 } //01 00 
		$a_01_1 = {6a 4d 8d 85 24 ff ff ff 50 e8 } //01 00 
		$a_01_2 = {30 4d 0f 8a 4d 0f 88 0c 10 40 3b c6 72 e3 } //00 00 
	condition:
		any of ($a_*)
 
}