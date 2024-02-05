
rule Trojan_Win64_Zzinfor_LK_MTB{
	meta:
		description = "Trojan:Win64/Zzinfor.LK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 02 00 "
		
	strings :
		$a_01_0 = {41 b9 04 00 00 00 41 b8 00 10 00 00 8b d0 33 c9 ff } //01 00 
		$a_01_1 = {8a 06 48 83 c6 01 88 07 48 83 c7 01 49 c7 c1 02 00 00 00 02 d2 75 07 } //00 00 
	condition:
		any of ($a_*)
 
}