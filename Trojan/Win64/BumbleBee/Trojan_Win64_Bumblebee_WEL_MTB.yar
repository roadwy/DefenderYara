
rule Trojan_Win64_Bumblebee_WEL_MTB{
	meta:
		description = "Trojan:Win64/Bumblebee.WEL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 03 00 00 05 00 "
		
	strings :
		$a_03_0 = {c1 ea 08 01 83 90 01 04 48 8b 83 90 01 04 88 14 01 ff 43 90 01 01 48 63 4b 74 48 8b 83 90 01 04 44 88 04 01 8b 83 90 01 04 8b 93 90 01 04 35 40 33 0e 00 0f af 43 90 01 01 ff 43 90 01 01 01 93 90 01 04 33 43 90 01 01 83 f0 01 89 43 90 01 01 49 81 f9 90 01 04 0f 8c 90 00 } //01 00 
		$a_01_1 = {5a 41 52 53 59 36 32 } //01 00  ZARSY62
		$a_01_2 = {52 4a 56 51 61 31 31 59 } //00 00  RJVQa11Y
	condition:
		any of ($a_*)
 
}