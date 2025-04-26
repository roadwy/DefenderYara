
rule Trojan_Win64_CobaltStrike_LKM_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.LKM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {51 6c 5a 79 6c 54 35 57 4d 5a 63 47 49 41 79 54 55 62 53 47 6e 41 65 72 52 2e 72 65 73 6f 75 72 63 65 73 } //1 QlZylT5WMZcGIAyTUbSGnAerR.resources
		$a_01_1 = {4e 65 77 20 50 72 6f 6a 65 63 74 20 32 2e 65 78 65 } //1 New Project 2.exe
		$a_01_2 = {48 62 72 5a 61 38 } //1 HbrZa8
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}