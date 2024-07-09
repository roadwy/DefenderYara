
rule PWS_Win32_QQpass_CJZ{
	meta:
		description = "PWS:Win32/QQpass.CJZ,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {74 6d 2e 65 78 65 00 00 71 71 2e 65 78 65 00 } //1
		$a_00_1 = {5c 51 51 5c 52 65 67 69 73 74 72 79 2e 64 62 } //1 \QQ\Registry.db
		$a_00_2 = {47 65 74 55 70 64 61 74 65 43 6f 6d 6d 6f 6e 44 61 74 61 46 6f 6c 64 65 72 } //1 GetUpdateCommonDataFolder
		$a_02_3 = {8b f4 6a 00 6a 02 8b fc 6a 00 6a 08 ff 15 ?? ?? ?? ?? 3b fc e8 ?? ?? ?? ?? 50 6a 08 ff 15 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_02_3  & 1)*1) >=4
 
}