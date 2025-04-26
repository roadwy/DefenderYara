
rule Backdoor_Win32_Knockex_C{
	meta:
		description = "Backdoor:Win32/Knockex.C,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 03 00 00 "
		
	strings :
		$a_02_0 = {b8 63 00 00 00 8b 7d f0 f2 ae 83 f9 00 0f 84 ?? ?? 00 00 81 3f 6f 6d 6d 61 75 ed 66 81 7f 04 6e 64 75 e5 80 7f 06 7c } //1
		$a_02_1 = {8b 7d 08 8b f7 b3 ?? ac 32 c3 aa fe c3 84 c0 75 f6 61 c9 c2 04 00 55 8b ec 60 8b 7d 08 8b f7 b3 ?? 66 ad 32 c3 66 ab fe c3 84 c0 } //1
		$a_02_2 = {ff 75 08 5f 57 5e b3 ?? ac 32 c3 aa fe c3 84 c0 75 f6 61 c9 c2 04 00 55 8b ec 60 ff 75 08 5f 8b f7 b3 ?? 66 ad 32 c3 66 ab fe c3 84 c0 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1+(#a_02_2  & 1)*1) >=1
 
}