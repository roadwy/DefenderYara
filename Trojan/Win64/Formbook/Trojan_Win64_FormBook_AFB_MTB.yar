
rule Trojan_Win64_FormBook_AFB_MTB{
	meta:
		description = "Trojan:Win64/FormBook.AFB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {48 89 44 24 08 48 89 5c 24 10 48 89 4c 24 18 48 89 7c 24 20 40 88 74 24 28 44 88 44 24 29 e8 77 f0 05 00 48 8b 44 24 08 48 8b 5c 24 10 48 8b 4c 24 18 48 8b 7c 24 20 0f b6 74 24 28 44 0f b6 44 24 29 } //00 00 
	condition:
		any of ($a_*)
 
}