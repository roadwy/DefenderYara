
rule VirTool_Win32_Abjector_C_MTB{
	meta:
		description = "VirTool:Win32/Abjector.C!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_02_0 = {50 51 51 8d 85 ?? ?? ?? ?? [0-07] 50 51 [0-03] c7 85 90 1b 00 01 00 00 00 ff 15 [0-29] 6a 00 b8 00 00 10 00 8d 0c 37 2b c7 50 51 [0-03] ff 15 } //1
		$a_02_1 = {80 3c 37 20 74 ?? 56 47 ff [0-05] 3b f8 7c [0-1b] 20 [0-02] e8 [0-06] 83 f8 01 7e 08 8d 46 01 03 c7 89 45 ?? c6 04 37 00 } //1
		$a_02_2 = {50 6a 08 ff 15 ?? ?? ?? ?? 50 ff 15 ?? ?? ?? ?? 85 c0 [0-07] 8d 45 ?? 89 75 ?? 50 6a 04 8d 45 e8 50 [0-02] 6a ?? ff 75 fc ff 15 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1+(#a_02_2  & 1)*1) >=3
 
}