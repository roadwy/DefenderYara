
rule Ransom_Win32_Lebanacrypt_A{
	meta:
		description = "Ransom:Win32/Lebanacrypt.A,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 0d 00 00 "
		
	strings :
		$a_80_0 = {53 48 41 44 4f 57 5f 43 4f 50 59 5f 44 49 52 53 } //SHADOW_COPY_DIRS  1
		$a_80_1 = {44 49 53 41 4c 4c 4f 57 5f 41 50 50 5f 52 45 44 49 52 45 43 54 53 } //DISALLOW_APP_REDIRECTS  1
		$a_80_2 = {43 4f 44 45 5f 44 4f 57 4e 4c 4f 41 44 5f 44 49 53 41 42 4c 45 44 } //CODE_DOWNLOAD_DISABLED  1
		$a_80_3 = {44 49 53 41 4c 4c 4f 57 5f 41 50 50 5f 42 41 53 45 5f 50 52 4f 42 49 4e 47 } //DISALLOW_APP_BASE_PROBING  1
		$a_80_4 = {42 49 4e 50 41 54 48 5f 50 52 4f 42 45 5f 4f 4e 4c 59 } //BINPATH_PROBE_ONLY  1
		$a_80_5 = {69 43 6f 72 65 58 23 31 33 33 37 } //iCoreX#1337  2
		$a_80_6 = {61 6e 6e 61 62 65 6c 6c 65 38 35 78 39 74 62 78 69 79 6b 69 2e 6f 6e 69 6f 6e } //annabelle85x9tbxiyki.onion  3
		$a_80_7 = {61 6e 6e 61 62 65 6c 6c 65 35 39 6a 33 6d 62 74 79 79 6b 69 2e 6f 6e 69 6f 6e } //annabelle59j3mbtyyki.onion  3
		$a_03_8 = {bb e0 07 8e c3 8e db b8 16 02 b9 02 00 b6 00 bb 00 00 cd 13 31 c0 89 c3 89 c1 89 c2 be 00 00 bf 90 01 02 ac 81 fe 90 01 02 73 31 3c 80 73 02 eb 0f 90 00 } //5
		$a_03_9 = {b9 00 20 00 00 f3 a5 5f 5e 6a 00 8d 45 90 01 01 50 68 00 80 00 00 8d 85 90 01 02 ff ff 50 53 e8 90 00 } //5
		$a_80_10 = {73 68 75 74 64 6f 77 6e 2e 65 78 65 20 2d 72 20 2d 66 20 2d 74 20 30 } //shutdown.exe -r -f -t 0  2
		$a_80_11 = {74 61 73 6b 6b 69 6c 6c 2e 65 78 65 20 2f 46 20 2f 49 4d 20 77 69 6e 69 6e 69 74 2e 65 78 65 } //taskkill.exe /F /IM wininit.exe  2
		$a_80_12 = {50 68 79 73 69 63 61 6c 44 72 69 76 65 34 } //PhysicalDrive4  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*2+(#a_80_6  & 1)*3+(#a_80_7  & 1)*3+(#a_03_8  & 1)*5+(#a_03_9  & 1)*5+(#a_80_10  & 1)*2+(#a_80_11  & 1)*2+(#a_80_12  & 1)*1) >=10
 
}