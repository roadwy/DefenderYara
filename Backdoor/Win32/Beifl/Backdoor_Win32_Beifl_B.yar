
rule Backdoor_Win32_Beifl_B{
	meta:
		description = "Backdoor:Win32/Beifl.B,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {66 c7 44 44 ?? 6c 00 66 c7 44 44 ?? 6e 00 66 c7 44 44 ?? 6b 00 } //1
		$a_03_1 = {66 c7 84 45 ?? ?? ff ff 6c 00 66 c7 84 45 ?? ?? ff ff 6e 00 66 c7 84 45 ?? ?? ff ff 6b 00 } //1
		$a_01_2 = {8a 07 3c 11 76 63 25 ff 00 00 00 83 e8 11 47 } //2
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*2) >=3
 
}