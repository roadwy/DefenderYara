
rule Backdoor_Win32_Phdet_V{
	meta:
		description = "Backdoor:Win32/Phdet.V,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_01_0 = {c7 45 e4 6b 00 65 00 c7 45 e8 72 00 6e 00 c7 45 ec 65 00 6c 00 c7 45 f0 33 00 32 00 c7 45 f4 2e 00 64 00 c7 45 f8 6c 00 6c 00 } //1
		$a_03_1 = {61 64 76 61 c7 45 ?? 70 69 33 32 c7 45 ?? 2e 64 6c 6c } //1
		$a_03_2 = {83 ec 10 c7 45 ec 5a 00 00 00 c7 45 e0 46 00 00 00 c7 45 e8 5a 00 00 00 c7 45 e4 46 00 00 00 6a 01 8d ?? e0 ?? e8 ?? ?? ff } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=2
 
}