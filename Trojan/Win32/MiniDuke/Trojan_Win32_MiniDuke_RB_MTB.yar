
rule Trojan_Win32_MiniDuke_RB_MTB{
	meta:
		description = "Trojan:Win32/MiniDuke.RB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {0f b7 4d fe c1 e0 0d 33 c1 33 05 90 01 04 69 c0 0d 66 19 00 05 6c 59 88 3c 33 d2 f7 75 0c 89 15 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}