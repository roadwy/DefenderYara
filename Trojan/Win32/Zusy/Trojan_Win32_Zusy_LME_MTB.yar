
rule Trojan_Win32_Zusy_LME_MTB{
	meta:
		description = "Trojan:Win32/Zusy.LME!MTB,SIGNATURE_TYPE_PEHSTR_EXT,23 00 23 00 03 00 00 "
		
	strings :
		$a_03_0 = {c7 45 a4 8a a5 08 00 bb e3 14 00 00 c7 45 c4 9f 0a 00 00 89 65 fc 81 45 fc 64 02 00 00 89 6d f8 81 45 f8 c0 01 00 00 8d 0d 68 a6 48 00 8b 41 f0 89 45 f4 8b 41 ec 89 45 f0 c7 45 d8 c0 70 2c 00 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8b 0d 68 a6 48 00 b2 01 } //20
		$a_01_1 = {33 c0 89 43 60 33 c0 89 83 84 00 00 00 c7 43 5c 18 00 00 ff c7 43 78 f4 01 00 00 c6 43 7c 01 33 c0 89 83 80 00 00 00 c7 43 74 c4 09 00 00 c6 83 88 00 00 00 00 c6 83 9d 00 00 00 01 c6 83 b4 00 00 00 01 b2 01 a1 } //10
		$a_01_2 = {71 65 74 77 65 74 72 71 77 65 72 } //5 qetwetrqwer
	condition:
		((#a_03_0  & 1)*20+(#a_01_1  & 1)*10+(#a_01_2  & 1)*5) >=35
 
}