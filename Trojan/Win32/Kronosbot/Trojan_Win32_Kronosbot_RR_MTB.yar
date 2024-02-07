
rule Trojan_Win32_Kronosbot_RR_MTB{
	meta:
		description = "Trojan:Win32/Kronosbot.RR!MTB,SIGNATURE_TYPE_PEHSTR,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {73 65 74 5f 75 72 6c 20 68 74 74 70 2a 62 62 76 61 2a 2e 6d 78 2a 20 47 50 } //01 00  set_url http*bbva*.mx* GP
		$a_01_1 = {64 61 74 61 5f 69 6e 6a 65 63 74 } //01 00  data_inject
		$a_01_2 = {59 38 7b 4f 74 63 57 6f 40 72 46 62 5b 61 67 39 4b 49 6a 6d 5d 5d 57 31 57 4c 52 38 71 53 38 } //01 00  Y8{OtcWo@rFb[ag9KIjm]]W1WLR8qS8
		$a_01_3 = {43 6f 6c 6c 65 63 74 49 6e 66 6f } //01 00  CollectInfo
		$a_01_4 = {63 6f 6e 74 69 6e 75 65 6e 75 6d 73 79 6e 63 2e 6d 6c } //00 00  continuenumsync.ml
	condition:
		any of ($a_*)
 
}