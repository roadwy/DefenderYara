
rule Trojan_BAT_Seraph_SG_MTB{
	meta:
		description = "Trojan:BAT/Seraph.SG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 02 00 "
		
	strings :
		$a_00_0 = {25 47 20 ab 00 00 00 61 d2 52 06 17 58 0a 06 03 8e 69 32 e5 } //02 00 
		$a_80_1 = {2f 2f 64 6f 77 6e 6c 6f 61 64 66 69 6c 65 6b 65 65 2e 6c 6f 6c 2f } ////downloadfilekee.lol/  00 00 
	condition:
		any of ($a_*)
 
}