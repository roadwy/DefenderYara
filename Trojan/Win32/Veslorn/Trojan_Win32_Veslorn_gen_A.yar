
rule Trojan_Win32_Veslorn_gen_A{
	meta:
		description = "Trojan:Win32/Veslorn.gen!A,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 03 00 00 "
		
	strings :
		$a_02_0 = {c6 44 24 31 02 66 89 7c 24 36 88 4c 24 54 88 44 24 55 bd ?? ?? ?? ?? eb 02 33 ff ff d3 99 b9 fa 00 00 00 } //1
		$a_02_1 = {8d 4c 24 14 6a 10 51 6a 00 52 68 ?? ?? 00 10 57 ff ?? 4e 75 ?? 83 3d ?? ?? 00 10 01 75 ?? 5d 5b 6a 00 ff 15 } //1
		$a_02_2 = {8d 4c 24 14 6a 10 51 6a 00 52 68 ?? ?? 00 10 57 ff d5 4e 75 e1 83 3d ?? ?? 00 10 01 75 cb 6a 00 ff 15 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1+(#a_02_2  & 1)*1) >=1
 
}