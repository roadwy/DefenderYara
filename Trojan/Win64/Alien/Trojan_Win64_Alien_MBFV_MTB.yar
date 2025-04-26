
rule Trojan_Win64_Alien_MBFV_MTB{
	meta:
		description = "Trojan:Win64/Alien.MBFV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 04 00 00 "
		
	strings :
		$a_03_0 = {48 89 44 24 20 4c 8d 0d ?? ?? ?? ?? 33 d2 44 8d 42 01 48 8d 0d fe a6 01 00 } //5
		$a_01_1 = {44 65 66 61 75 6c 74 42 72 6f 77 73 65 72 } //1 DefaultBrowser
		$a_01_2 = {63 68 72 6d 69 6e 73 74 } //1 chrminst
		$a_01_3 = {61 6d 73 63 6c 6f 75 64 68 6f 73 74 2e 63 6f 6d } //1 amscloudhost.com
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=8
 
}