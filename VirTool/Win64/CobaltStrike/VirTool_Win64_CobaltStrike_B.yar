
rule VirTool_Win64_CobaltStrike_B{
	meta:
		description = "VirTool:Win64/CobaltStrike.B,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_03_0 = {81 f9 8e 4e 0e ec 74 ?? 81 f9 aa fc 0d 7c 74 ?? 81 f9 54 ca af 91 74 } //1
		$a_01_1 = {0f b7 45 16 66 23 c1 66 f7 d8 b8 00 40 00 00 45 1b e4 41 83 e4 3c 41 83 c4 04 44 89 64 24 20 66 85 45 16 } //1
		$a_01_2 = {ff d6 45 33 db 48 85 db 75 21 8b 55 50 45 8b cc 33 c9 41 b8 00 30 00 00 41 ff d5 } //1
		$a_01_3 = {b9 40 00 00 00 48 03 f3 48 8b c5 f3 a4 b9 40 00 00 00 44 30 00 49 03 c5 49 2b cd } //1
		$a_01_4 = {41 8b c7 80 34 28 69 48 ff c0 48 3d 00 10 00 00 7c f1 48 8d 4c 24 20 41 b8 00 10 00 00 48 8b d5 e8 } //1
		$a_03_5 = {62 65 61 63 6f 6e [0-04] 2e 64 6c 6c 00 } //1
		$a_01_6 = {52 65 66 6c 65 63 74 69 76 65 4c 6f 61 64 65 72 } //1 ReflectiveLoader
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_03_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}