
rule Backdoor_Win32_Plugx_gen_A{
	meta:
		description = "Backdoor:Win32/Plugx.gen!A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8a 0c 30 80 e9 ?? 80 f1 ?? 80 c1 ?? 88 0c 30 40 3b c3 76 ec ff d6 } //1
		$a_03_1 = {c6 06 68 b0 ff 88 46 01 88 46 02 88 46 03 88 46 04 c6 46 05 68 b8 ?? ?? ?? ?? 88 46 06 b8 ?? ?? ?? ?? c1 e8 08 88 46 07 b9 ?? ?? ?? ?? c1 e9 10 88 4e 08 ba ?? ?? ?? ?? c1 ea 18 88 56 09 8d 44 24 ?? 50 c6 46 0a c3 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}