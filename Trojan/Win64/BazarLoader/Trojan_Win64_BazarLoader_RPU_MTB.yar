
rule Trojan_Win64_BazarLoader_RPU_MTB{
	meta:
		description = "Trojan:Win64/BazarLoader.RPU!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {41 80 f3 ff 44 88 d3 80 f3 ff 40 b6 01 40 80 f6 00 44 88 df 40 80 e7 00 41 20 f1 40 88 dd 40 80 e5 00 41 20 f2 44 08 cf } //00 00 
	condition:
		any of ($a_*)
 
}