
rule VirTool_Win32_VBInject_YJ{
	meta:
		description = "VirTool:Win32/VBInject.YJ,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {56 8b 74 24 0c 57 8b 3e 81 ff 00 01 00 00 72 06 ff 15 ?? ?? ?? 00 8b 0d ?? ?? ?? ?? 8a 44 24 0c 68 ?? ?? ?? ?? 88 04 39 ff 15 ?? ?? ?? ?? 8b 0e 5f 03 c1 70 06 89 06 5e c2 08 00 } //1
		$a_01_1 = {5a 00 4e 00 57 00 6c 00 58 00 47 00 6f 00 4b 00 50 00 77 00 4b 00 41 00 74 00 2f 00 48 00 53 00 31 00 38 00 79 00 51 00 4e 00 50 00 6f 00 51 00 56 00 38 00 50 00 54 00 64 00 46 00 35 00 78 00 66 00 4a 00 4e 00 73 00 36 00 2f 00 4e 00 39 00 56 00 44 00 59 00 3d 00 } //1 ZNWlXGoKPwKAt/HS18yQNPoQV8PTdF5xfJNs6/N9VDY=
		$a_01_2 = {2b 00 67 00 73 00 44 00 53 00 78 00 6f 00 71 00 44 00 44 00 47 00 77 00 58 00 47 00 63 00 59 00 64 00 75 00 74 00 77 00 6f 00 33 00 50 00 75 00 6b 00 50 00 56 00 68 00 75 00 73 00 57 00 59 00 78 00 50 00 61 00 67 00 58 00 32 00 32 00 43 00 47 00 4e 00 41 00 3d 00 } //1 +gsDSxoqDDGwXGcYdutwo3PukPVhusWYxPagX22CGNA=
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}