
rule Trojan_Win64_IcedID_GHC_MTB{
	meta:
		description = "Trojan:Win64/IcedID.GHC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {43 79 77 32 36 39 } //1 Cyw269
		$a_01_1 = {48 74 74 75 39 39 32 6f 49 33 } //1 Httu992oI3
		$a_01_2 = {4b 48 6f 36 } //1 KHo6
		$a_01_3 = {53 59 64 67 79 75 38 31 36 71 42 47 } //1 SYdgyu816qBG
		$a_01_4 = {56 58 62 61 72 37 37 34 } //1 VXbar774
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}