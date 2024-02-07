
rule Trojan_Win32_VBObfuse_SS_MTB{
	meta:
		description = "Trojan:Win32/VBObfuse.SS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {55 00 6c 00 4e 00 53 00 6a 00 62 00 71 00 4e 00 6f 00 45 00 39 00 77 00 50 00 4e 00 44 00 79 00 37 00 33 00 } //01 00  UlNSjbqNoE9wPNDy73
		$a_01_1 = {70 00 75 00 5a 00 49 00 41 00 4e 00 56 00 4b 00 6b 00 69 00 70 00 79 00 69 00 71 00 64 00 46 00 76 00 6c 00 31 00 58 00 57 00 77 00 6f 00 70 00 36 00 47 00 64 00 64 00 38 00 38 00 } //01 00  puZIANVKkipyiqdFvl1XWwop6Gdd88
		$a_01_2 = {72 00 6b 00 57 00 66 00 34 00 4d 00 4c 00 71 00 31 00 31 00 34 00 } //00 00  rkWf4MLq114
	condition:
		any of ($a_*)
 
}