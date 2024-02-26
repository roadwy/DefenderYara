
rule Trojan_Win64_Coinminer_RB_MTB{
	meta:
		description = "Trojan:Win64/Coinminer.RB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {41 89 c2 41 83 e2 1f 45 32 0c 12 44 88 0c 07 48 ff c0 48 39 c6 74 ac } //00 00 
	condition:
		any of ($a_*)
 
}