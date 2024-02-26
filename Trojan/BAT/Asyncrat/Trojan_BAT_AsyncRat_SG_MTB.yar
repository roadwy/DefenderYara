
rule Trojan_BAT_AsyncRat_SG_MTB{
	meta:
		description = "Trojan:BAT/AsyncRat.SG!MTB,SIGNATURE_TYPE_PEHSTR,03 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {55 72 69 48 6f 73 74 4e 61 6d 65 54 79 70 65 } //01 00  UriHostNameType
		$a_01_1 = {52 61 74 43 6c 69 65 6e 74 54 65 73 74 } //01 00  RatClientTest
		$a_01_2 = {5c 52 61 74 43 6c 69 65 6e 74 54 65 73 74 2e 70 64 62 } //01 00  \RatClientTest.pdb
		$a_01_3 = {48 00 69 00 20 00 70 00 6f 00 6e 00 69 00 74 00 61 00 } //00 00  Hi ponita
	condition:
		any of ($a_*)
 
}