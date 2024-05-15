
rule Trojan_BAT_AsyncRAT_RDV_MTB{
	meta:
		description = "Trojan:BAT/AsyncRAT.RDV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {48 74 69 6c 69 74 79 20 48 69 65 77 } //01 00  Htility Hiew
		$a_01_1 = {56 48 44 20 49 6d 61 67 65 } //01 00  VHD Image
		$a_01_2 = {73 65 72 76 65 72 31 } //00 00  server1
	condition:
		any of ($a_*)
 
}