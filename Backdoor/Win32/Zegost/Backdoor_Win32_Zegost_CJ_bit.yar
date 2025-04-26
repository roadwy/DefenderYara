
rule Backdoor_Win32_Zegost_CJ_bit{
	meta:
		description = "Backdoor:Win32/Zegost.CJ!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {8b 45 08 8a 08 32 4d ?? 02 4d ?? 88 08 b8 ?? ?? ?? 00 c3 } //1
		$a_03_1 = {8b 45 08 8b 78 3c 03 f8 81 3f 50 45 00 00 75 34 8b 35 ?? ?? ?? 00 6a 04 68 00 20 00 00 ff 77 ?? ff 77 ?? ff d6 } //1
		$a_01_2 = {53 68 65 6c 6c 65 78 00 } //1 桓汥敬x
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}