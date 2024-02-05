
rule Trojan_BAT_Xmrig_NEAG_MTB{
	meta:
		description = "Trojan:BAT/Xmrig.NEAG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 02 00 00 0a 00 "
		
	strings :
		$a_01_0 = {09 11 04 18 5b 07 11 04 18 6f 25 00 00 0a 1f 10 28 26 00 00 0a 9c 11 04 18 58 13 04 11 04 08 32 df } //05 00 
		$a_01_1 = {4c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 46 00 6f 00 72 00 6d 00 73 00 41 00 70 00 70 00 37 00 36 00 6f 00 61 00 64 00 } //00 00 
	condition:
		any of ($a_*)
 
}