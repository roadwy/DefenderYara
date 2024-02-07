
rule Trojan_BAT_AsyncRat_CBYY_MTB{
	meta:
		description = "Trojan:BAT/AsyncRat.CBYY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {43 00 78 00 66 00 61 00 79 00 77 00 76 00 47 00 57 00 63 00 32 00 77 00 56 00 44 00 68 00 45 00 } //01 00  CxfaywvGWc2wVDhE
		$a_01_1 = {37 00 7a 00 4b 00 55 00 67 00 74 00 79 00 38 00 70 00 42 00 56 00 4a 00 47 00 4b 00 50 00 4b 00 } //00 00  7zKUgty8pBVJGKPK
	condition:
		any of ($a_*)
 
}