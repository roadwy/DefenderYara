
rule Trojan_Win64_AveMaria_CRHX_MTB{
	meta:
		description = "Trojan:Win64/AveMaria.CRHX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {48 8b c7 83 e0 0f 0f b6 04 10 f6 d0 30 04 39 48 ff c7 48 3b 3e 72 } //00 00 
	condition:
		any of ($a_*)
 
}