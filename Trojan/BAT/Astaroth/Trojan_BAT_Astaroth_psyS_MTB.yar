
rule Trojan_BAT_Astaroth_psyS_MTB{
	meta:
		description = "Trojan:BAT/Astaroth.psyS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 01 00 00 07 00 "
		
	strings :
		$a_01_0 = {73 27 01 00 06 0d 09 07 08 9a 7d be 00 00 04 28 b3 01 00 0a 09 fe 06 28 01 00 06 73 78 00 00 0a 6f b4 01 00 0a 26 08 17 58 0c 08 07 8e 69 32 d0 } //00 00 
	condition:
		any of ($a_*)
 
}