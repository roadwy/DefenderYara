
rule Backdoor_Win32_Phdet_R{
	meta:
		description = "Backdoor:Win32/Phdet.R,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {0f b7 42 06 39 45 f4 73 36 68 ?? ?? ?? ?? 8b 4d f8 51 e8 ?? ?? 00 00 83 c4 } //1
		$a_03_1 = {68 9c 45 6e a0 6a ?? e8 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}