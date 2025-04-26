
rule VirTool_Win32_DelfInject_W{
	meta:
		description = "VirTool:Win32/DelfInject.W,SIGNATURE_TYPE_PEHSTR_EXT,19 00 19 00 05 00 00 "
		
	strings :
		$a_00_0 = {63 72 79 70 74 6f 63 6f 64 65 } //5 cryptocode
		$a_00_1 = {43 6f 64 65 72 73 43 72 79 70 74 } //5 CodersCrypt
		$a_02_2 = {43 33 ff a1 ?? ?? ?? 00 8a 04 38 a2 ?? ?? ?? 00 a0 ?? ?? ?? 00 c0 c8 ?? a2 ?? ?? ?? 00 a1 ?? ?? ?? 00 8a 15 ?? ?? ?? 00 88 14 38 47 4b 75 } //10
		$a_01_3 = {36 00 00 00 ff ff ff ff 01 00 00 00 37 00 00 00 ff ff ff ff 01 00 00 00 38 00 00 00 ff ff ff ff 01 00 00 00 39 00 00 00 ff ff ff ff 01 00 00 00 30 00 00 00 ff ff ff ff } //1
		$a_02_4 = {48 5a 8b ca 99 f7 f9 42 a1 ?? ?? ?? 00 8a 44 10 ff 8b 15 ?? ?? ?? 00 8a 14 3a 32 c2 8b 15 ?? ?? ?? 00 88 04 3a } //10
	condition:
		((#a_00_0  & 1)*5+(#a_00_1  & 1)*5+(#a_02_2  & 1)*10+(#a_01_3  & 1)*1+(#a_02_4  & 1)*10) >=25
 
}