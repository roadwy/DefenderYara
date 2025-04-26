
rule Trojan_Win64_Autorun_NA_MTB{
	meta:
		description = "Trojan:Win64/Autorun.NA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {0f 84 e6 00 00 00 48 8b 05 95 fa 0d 00 48 8d 1c b6 48 c1 e3 03 48 01 d8 48 89 78 ?? c7 00 00 00 00 00 e8 23 0b 00 00 8b 57 ?? 41 b8 30 00 00 00 48 8d 0c 10 48 8b 05 67 fa 0d 00 48 8d 54 24 ?? 48 89 4c 18 } //3
		$a_01_1 = {31 00 38 00 36 00 2e 00 32 00 36 00 2e 00 31 00 30 00 37 00 2e 00 31 00 38 00 38 00 } //1 186.26.107.188
	condition:
		((#a_03_0  & 1)*3+(#a_01_1  & 1)*1) >=4
 
}