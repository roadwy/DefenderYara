
rule Trojan_Win64_Dridex_QV_MTB{
	meta:
		description = "Trojan:Win64/Dridex.QV!MTB,SIGNATURE_TYPE_PEHSTR,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_01_0 = {66 44 8b 9c 24 ce 01 00 00 44 89 ce 09 f6 89 b4 24 bc 01 00 00 4c 89 94 24 a0 01 00 00 8a 9c 24 bb 01 00 00 28 d9 49 89 c2 88 8c 24 bb 01 00 00 48 89 c1 4c 89 54 24 50 48 89 54 24 48 88 5c 24 47 4c 89 44 24 38 44 89 4c 24 34 66 44 89 5c 24 32 } //00 00 
	condition:
		any of ($a_*)
 
}