
rule Trojan_Win64_Alien_MBFV_MTB{
	meta:
		description = "Trojan:Win64/Alien.MBFV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 04 00 00 05 00 "
		
	strings :
		$a_03_0 = {48 89 44 24 20 4c 8d 0d 90 01 04 33 d2 44 8d 42 01 48 8d 0d fe a6 01 00 90 00 } //01 00 
		$a_01_1 = {44 65 66 61 75 6c 74 42 72 6f 77 73 65 72 } //01 00  DefaultBrowser
		$a_01_2 = {63 68 72 6d 69 6e 73 74 } //01 00  chrminst
		$a_01_3 = {61 6d 73 63 6c 6f 75 64 68 6f 73 74 2e 63 6f 6d } //00 00  amscloudhost.com
	condition:
		any of ($a_*)
 
}