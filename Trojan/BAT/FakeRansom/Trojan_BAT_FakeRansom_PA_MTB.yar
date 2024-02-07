
rule Trojan_BAT_FakeRansom_PA_MTB{
	meta:
		description = "Trojan:BAT/FakeRansom.PA!MTB,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {4d 00 61 00 73 00 73 00 46 00 69 00 6c 00 65 00 52 00 65 00 6e 00 61 00 6d 00 65 00 72 00 5f 00 66 00 61 00 6b 00 65 00 72 00 61 00 6e 00 73 00 6f 00 6d 00 77 00 61 00 72 00 65 00 } //01 00  MassFileRenamer_fakeransomware
		$a_01_1 = {79 00 6f 00 75 00 72 00 20 00 66 00 69 00 6c 00 65 00 73 00 20 00 68 00 61 00 76 00 65 00 20 00 62 00 65 00 65 00 6e 00 20 00 65 00 6e 00 63 00 72 00 79 00 70 00 74 00 65 00 64 00 } //01 00  your files have been encrypted
		$a_01_2 = {57 00 61 00 6e 00 61 00 20 00 44 00 65 00 63 00 72 00 79 00 70 00 74 00 30 00 72 00 } //01 00  Wana Decrypt0r
		$a_01_3 = {62 00 69 00 74 00 63 00 6f 00 69 00 6e 00 } //00 00  bitcoin
	condition:
		any of ($a_*)
 
}