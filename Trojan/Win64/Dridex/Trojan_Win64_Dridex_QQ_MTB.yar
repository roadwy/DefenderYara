
rule Trojan_Win64_Dridex_QQ_MTB{
	meta:
		description = "Trojan:Win64/Dridex.QQ!MTB,SIGNATURE_TYPE_PEHSTR,14 00 14 00 02 00 00 0a 00 "
		
	strings :
		$a_01_0 = {44 8a 0c 08 89 54 24 4c 48 8b 44 24 18 46 8a 14 00 45 28 ca 48 8b 4c 24 08 46 88 14 01 8b 54 24 5c } //0a 00 
		$a_01_1 = {33 4c 24 24 89 4c 24 24 4c 8b 44 24 18 45 8a 0c 00 4c 8b 54 24 08 45 88 0c 02 48 8b 4c 24 28 48 d3 ea } //00 00 
	condition:
		any of ($a_*)
 
}