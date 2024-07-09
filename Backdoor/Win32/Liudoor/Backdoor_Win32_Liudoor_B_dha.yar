
rule Backdoor_Win32_Liudoor_B_dha{
	meta:
		description = "Backdoor:Win32/Liudoor.B!dha,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {73 76 63 68 6f 73 74 64 6c 6c 73 65 72 76 65 72 2e 64 6c 6c 00 } //1
		$a_01_1 = {53 75 63 63 00 00 00 00 46 61 69 6c 00 } //1
		$a_03_2 = {55 8b ee 81 ed ?? ?? ?? ?? 8a 84 2a ?? ?? ?? ?? 8b fe 34 1f 83 c9 ff 88 82 ?? ?? ?? ?? 33 c0 42 f2 ae f7 d1 49 3b d1 72 e0 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}