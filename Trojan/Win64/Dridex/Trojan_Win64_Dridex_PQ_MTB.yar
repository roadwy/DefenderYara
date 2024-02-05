
rule Trojan_Win64_Dridex_PQ_MTB{
	meta:
		description = "Trojan:Win64/Dridex.PQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {48 8b 04 24 48 0d 90 02 04 48 89 90 02 03 48 03 90 02 03 48 89 90 02 03 48 8b 90 02 03 48 39 c1 0f 84 90 02 04 e9 90 02 04 b8 90 02 04 89 c1 48 2b 90 02 03 48 89 90 02 03 8a 90 02 03 80 90 02 02 88 90 02 03 e9 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}