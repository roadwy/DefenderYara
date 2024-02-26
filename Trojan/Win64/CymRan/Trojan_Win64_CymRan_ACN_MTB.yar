
rule Trojan_Win64_CymRan_ACN_MTB{
	meta:
		description = "Trojan:Win64/CymRan.ACN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {53 55 56 57 41 54 41 56 41 57 48 83 ec 30 33 ed 48 8b da 4c 8b f9 48 85 d2 } //00 00 
	condition:
		any of ($a_*)
 
}