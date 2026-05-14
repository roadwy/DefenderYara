
rule VirTool_Win32_Rediresz_A{
	meta:
		description = "VirTool:Win32/Rediresz.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b d8 85 db ?? ?? ?? ?? ?? ?? 8b 35 1c 50 40 00 68 1c 56 40 00 53 ff ?? 68 2c 56 40 00 53 a3 34 71 40 00 ff ?? 8b 9d 0c fd ff ff a3 30 71 40 00 8b 4b 04 51 83 ff 02 } //1
		$a_03_1 = {8b f0 85 f6 ?? ?? 8b 0d 7c 50 40 00 ba 38 58 40 00 56 68 ?? 11 40 00 e8 ?? ?? ?? ?? 8b c8 ff ?? ?? ?? ?? ?? 8b c8 ff ?? ?? ?? ?? ?? ba f0 51 40 00 8b c8 e8 ?? ?? ?? ?? 8b ce e8 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}