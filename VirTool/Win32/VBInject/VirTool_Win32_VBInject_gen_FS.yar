
rule VirTool_Win32_VBInject_gen_FS{
	meta:
		description = "VirTool:Win32/VBInject.gen!FS,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {73 74 75 62 00 63 69 39 6d 2c 39 33 32 38 63 6d 33 6d 72 39 32 38 33 63 2c 72 2c 39 32 63 72 32 00 [0-05] 50 72 6f 79 65 63 74 6f } //1
		$a_01_1 = {4d 6f 64 75 6c 65 31 00 52 75 6e 50 65 00 00 00 63 6c 73 52 43 34 00 00 50 72 6f 79 65 63 74 6f 31 00 } //1
		$a_01_2 = {7e 00 7c 00 7c 00 7e 00 7c 00 7c 00 7e 00 4b 00 2d 00 49 00 2d 00 4e 00 2d 00 4b 00 2d 00 49 00 7e 00 7c 00 7c 00 7e 00 7c 00 7c 00 7e 00 } //1 ~||~||~K-I-N-K-I~||~||~
		$a_01_3 = {4e 00 50 00 55 00 4b 00 50 00 54 00 4e 00 49 00 51 00 51 00 57 00 45 00 51 00 46 00 59 00 52 00 42 00 53 00 59 00 57 00 4b 00 51 00 52 00 55 00 4c 00 4e 00 43 00 51 00 45 00 42 00 44 00 58 00 56 00 4f 00 45 00 44 00 58 00 54 00 56 00 48 00 } //1 NPUKPTNIQQWEQFYRBSYWKQRULNCQEBDXVOEDXTVH
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}