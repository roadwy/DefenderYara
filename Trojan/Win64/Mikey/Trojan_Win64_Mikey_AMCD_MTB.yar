
rule Trojan_Win64_Mikey_AMCD_MTB{
	meta:
		description = "Trojan:Win64/Mikey.AMCD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {41 8d 0c 30 41 ff c0 80 34 39 90 01 01 44 3b c0 72 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}