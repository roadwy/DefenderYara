
rule Trojan_Win64_Mikey_AMBC_MTB{
	meta:
		description = "Trojan:Win64/Mikey.AMBC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {49 39 c7 74 90 01 01 8a 4c 05 d0 41 30 4c 05 00 48 ff c0 eb 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}