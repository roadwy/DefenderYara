
rule Trojan_Win32_Amadey_NA_MTB{
	meta:
		description = "Trojan:Win32/Amadey.NA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b c1 c1 f8 10 88 04 3a 8b c1 c1 f8 08 88 44 3a 01 8b c2 88 4c 38 02 83 c7 03 83 6c 24 28 01 75 a3 } //10
		$a_01_1 = {8d 42 ff c1 e8 02 83 c6 02 40 } //5
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*5) >=15
 
}
rule Trojan_Win32_Amadey_NA_MTB_2{
	meta:
		description = "Trojan:Win32/Amadey.NA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 1d e5 36 5e 00 b9 ?? ?? ?? ?? c1 cb 04 89 05 f2 63 5e 00 81 2d ?? ?? ?? ?? ea dd f6 08 c1 cf 15 81 c7 07 8d ae 68 81 05 ?? ?? ?? ?? 81 31 e3 67 33 d3 } //3
		$a_03_1 = {c1 c2 13 21 15 ?? ?? ?? ?? 2b 0d d4 6d 5e 00 89 1d ?? ?? ?? ?? e8 53 96 fe ff e8 4b 01 0d 00 } //3
	condition:
		((#a_03_0  & 1)*3+(#a_03_1  & 1)*3) >=6
 
}