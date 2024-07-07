
rule Trojan_Win64_Bumblebee_ZAA_MTB{
	meta:
		description = "Trojan:Win64/Bumblebee.ZAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 03 00 00 "
		
	strings :
		$a_03_0 = {41 8b d0 c1 ea 08 88 14 01 ff 43 90 01 01 48 63 4b 90 01 01 48 8b 83 90 01 04 44 88 04 01 ff 43 90 01 01 8b 43 90 01 01 2d 90 01 04 31 83 90 01 04 8b 83 90 01 04 01 83 90 01 04 8b 43 90 01 01 33 43 90 01 01 83 f0 01 89 43 90 01 01 49 81 f9 90 01 04 0f 8c 90 00 } //5
		$a_01_1 = {42 61 73 69 63 4c 6f 61 64 } //1 BasicLoad
		$a_01_2 = {44 57 4a 4d 52 31 34 38 31 } //1 DWJMR1481
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=7
 
}