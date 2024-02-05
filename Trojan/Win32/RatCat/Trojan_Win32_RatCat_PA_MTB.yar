
rule Trojan_Win32_RatCat_PA_MTB{
	meta:
		description = "Trojan:Win32/RatCat.PA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {3c 39 7f d5 83 7d b4 19 73 90 01 01 ff 45 b4 2a c3 88 07 47 ff 4d b0 8a 02 42 3a c3 7d e4 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}