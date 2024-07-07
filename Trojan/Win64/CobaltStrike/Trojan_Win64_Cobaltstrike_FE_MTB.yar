
rule Trojan_Win64_Cobaltstrike_FE_MTB{
	meta:
		description = "Trojan:Win64/Cobaltstrike.FE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_01_0 = {0f b6 4c 14 08 44 89 04 24 89 54 24 04 44 88 54 14 08 41 8d 04 0a 43 88 0c 01 0f b6 c8 0f b6 44 0c 08 42 32 44 1f ff 41 88 43 } //1
		$a_00_1 = {44 3a 5c 73 76 6e 32 5c 6b 64 64 72 69 76 65 72 5c 6b 64 5f 64 72 69 76 65 72 5f 63 6f 6e 66 69 67 5c 78 36 34 5c 52 65 6c 65 61 73 65 5c 4b 44 44 72 69 76 65 72 53 65 74 74 69 6e 67 2e 70 64 62 } //65535 D:\svn2\kddriver\kd_driver_config\x64\Release\KDDriverSetting.pdb
	condition:
		((#a_01_0  & 1)*1+(#a_00_1  & 1)*65535) >=1
 
}