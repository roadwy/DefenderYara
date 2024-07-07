
rule Trojan_Win32_ShellcodeRunner_CO_MTB{
	meta:
		description = "Trojan:Win32/ShellcodeRunner.CO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {46 8a 84 35 90 01 02 ff ff 88 8c 35 90 01 02 ff ff 0f b6 c8 88 84 3d 90 01 02 ff ff 0f b6 84 35 90 01 02 ff ff 03 c8 0f b6 c1 8b 8d 90 01 02 ff ff 0f b6 84 05 90 01 02 ff ff 32 44 1a 08 88 04 11 42 81 fa 90 00 } //4
		$a_01_1 = {83 c4 0c 8d 44 24 30 50 8d 84 24 5c 01 00 00 50 ff 15 } //1
	condition:
		((#a_03_0  & 1)*4+(#a_01_1  & 1)*1) >=5
 
}