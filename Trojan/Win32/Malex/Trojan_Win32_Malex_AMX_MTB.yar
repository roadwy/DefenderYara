
rule Trojan_Win32_Malex_AMX_MTB{
	meta:
		description = "Trojan:Win32/Malex.AMX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {6a 01 6a 10 68 94 7a 42 00 68 06 7c 42 00 e8 ?? ?? ?? ?? 83 c4 10 6a 01 6a 10 68 a5 7a 42 00 68 06 7c 42 00 e8 ?? ?? ?? ?? 83 c4 10 6a 01 6a 10 68 b6 7a 42 00 68 06 7c 42 00 e8 ?? ?? ?? ?? 83 c4 10 6a 01 6a 10 ff 35 e4 7a 42 00 68 06 7c 42 00 e8 } //2
		$a_03_1 = {83 c4 1c ff 35 20 59 42 00 68 80 8d 42 00 68 28 9c 41 00 e8 ?? ?? ?? ?? 83 c4 0c 68 28 9c 41 00 68 a4 8d 42 00 68 30 97 41 00 } //1
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*1) >=3
 
}