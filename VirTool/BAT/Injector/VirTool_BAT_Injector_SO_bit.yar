
rule VirTool_BAT_Injector_SO_bit{
	meta:
		description = "VirTool:BAT/Injector.SO!bit,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 08 00 00 "
		
	strings :
		$a_01_0 = {54 00 47 00 39 00 68 00 5a 00 41 00 3d 00 3d 00 } //1 TG9hZA==
		$a_01_1 = {51 00 32 00 46 00 73 00 62 00 45 00 4a 00 35 00 54 00 6d 00 46 00 74 00 5a 00 51 00 3d 00 3d 00 } //1 Q2FsbEJ5TmFtZQ==
		$a_01_2 = {52 00 32 00 56 00 30 00 54 00 32 00 4a 00 71 00 5a 00 57 00 4e 00 30 00 56 00 6d 00 46 00 73 00 64 00 57 00 55 00 3d 00 } //1 R2V0T2JqZWN0VmFsdWU=
		$a_01_3 = {50 6f 73 74 5f 4d 61 72 6b 4d 61 69 6c 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //1 Post_MarkMail.Resources.resources
		$a_03_4 = {53 00 74 00 61 00 72 00 74 00 75 00 70 00 46 00 69 00 6c 00 65 00 [0-10] 52 00 75 00 6e 00 4f 00 6e 00 52 00 65 00 62 00 6f 00 6f 00 74 00 } //2
		$a_03_5 = {48 00 69 00 64 00 64 00 65 00 6e 00 41 00 74 00 72 00 69 00 62 00 [0-10] 44 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 65 00 72 00 24 00 } //2
		$a_03_6 = {44 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 65 00 72 00 49 00 [0-10] 41 00 6e 00 74 00 69 00 73 00 4f 00 70 00 74 00 69 00 6f 00 6e 00 73 00 } //2
		$a_03_7 = {42 00 79 00 70 00 61 00 73 00 73 00 4d 00 65 00 6d 00 6f 00 72 00 79 00 [0-10] 53 00 74 00 61 00 72 00 74 00 42 00 6f 00 74 00 4b 00 69 00 6c 00 6c 00 65 00 72 00 } //2
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_03_4  & 1)*2+(#a_03_5  & 1)*2+(#a_03_6  & 1)*2+(#a_03_7  & 1)*2) >=9
 
}