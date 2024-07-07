
rule VirTool_Win32_CeeInject_Z{
	meta:
		description = "VirTool:Win32/CeeInject.Z,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_00_0 = {5c 56 61 6c 68 61 6c 6c 61 43 72 79 70 74 65 72 5c 56 61 6c 68 61 6c 6c 61 53 74 75 62 5c 44 65 62 75 67 5c 56 61 6c 68 61 6c 6c 61 53 74 75 62 2e 70 64 62 } //1 \ValhallaCrypter\ValhallaStub\Debug\ValhallaStub.pdb
		$a_03_1 = {79 08 49 81 c9 00 ff ff ff 41 8b 45 08 03 85 90 01 04 0f b6 10 33 94 8d 90 01 04 8b 45 08 03 85 90 01 04 88 10 e9 90 00 } //1
		$a_03_2 = {c6 45 fc 0b 8d 85 90 01 04 50 8d 8d 90 01 04 51 e8 90 01 04 83 c4 08 c6 45 fc 0d 8d 8d 90 01 04 e8 90 01 04 68 90 01 04 8d 8d 90 01 04 e8 90 00 } //1
		$a_03_3 = {8b f4 50 6a 00 6a 00 ff 15 90 01 04 3b f4 e8 90 01 04 8b f4 ff 15 90 01 04 3b f4 e8 90 01 04 3d b7 00 00 00 75 66 68 90 01 04 8d 8d 90 01 04 e8 90 01 04 85 c0 75 52 90 00 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1) >=3
 
}