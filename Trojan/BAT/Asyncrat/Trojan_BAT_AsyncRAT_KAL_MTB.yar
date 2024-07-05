
rule Trojan_BAT_AsyncRAT_KAL_MTB{
	meta:
		description = "Trojan:BAT/AsyncRAT.KAL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {4d 00 6f 00 46 00 51 00 41 00 41 00 43 00 71 00 49 00 49 00 48 00 77 00 77 00 6f 00 45 } //01 00 
		$a_01_1 = {42 00 7a 00 45 00 41 00 41 00 41 00 43 00 67 00 6f 00 47 00 62 00 78 00 45 00 41 00 41 00 } //00 00  BzEAAACgoGbxEAA
	condition:
		any of ($a_*)
 
}