
rule Trojan_Win32_Gozi_MC_MTB{
	meta:
		description = "Trojan:Win32/Gozi.MC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {33 d2 f7 75 08 8a 82 90 01 04 32 04 0f 88 01 8b 45 0c 40 89 45 0c 3b c3 7c 90 00 } //01 00 
		$a_01_1 = {89 06 b2 30 8d 42 d0 0f be c8 8b 06 88 14 01 fe c2 80 fa 3a 7c } //00 00 
	condition:
		any of ($a_*)
 
}