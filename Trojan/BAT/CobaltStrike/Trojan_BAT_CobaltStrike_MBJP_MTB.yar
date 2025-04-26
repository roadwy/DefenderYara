
rule Trojan_BAT_CobaltStrike_MBJP_MTB{
	meta:
		description = "Trojan:BAT/CobaltStrike.MBJP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {25 47 06 11 0e 06 8e 69 5d 91 61 d2 52 11 0e 17 58 13 0e 11 0e 07 8e 69 32 de } //1
		$a_01_1 = {24 33 65 37 35 33 38 65 30 2d 35 36 65 38 2d 31 63 33 35 2d 61 39 38 35 2d 64 39 30 36 31 33 38 31 62 34 64 38 } //1 $3e7538e0-56e8-1c35-a985-d9061381b4d8
		$a_01_2 = {43 6f 6e 73 6f 6c 65 41 70 70 31 2e 65 78 65 } //1 ConsoleApp1.exe
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}