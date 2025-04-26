
rule Trojan_Win64_CobaltStrike_MBWJ_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.MBWJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {47 6f 20 62 75 69 6c 64 20 49 44 3a 20 22 5f 7a 59 45 50 53 74 6c 49 74 58 51 53 49 5a 78 } //2 Go build ID: "_zYEPStlItXQSIZx
		$a_01_1 = {61 78 79 31 2f 54 70 63 50 63 5a 77 42 74 51 59 63 43 4c 36 72 52 45 45 63 2f 38 58 4c 4a } //1 axy1/TpcPcZwBtQYcCL6rREEc/8XLJ
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}