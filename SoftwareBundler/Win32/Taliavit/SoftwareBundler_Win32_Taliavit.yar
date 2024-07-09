
rule SoftwareBundler_Win32_Taliavit{
	meta:
		description = "SoftwareBundler:Win32/Taliavit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {5c 6d 6f 63 6b 75 70 5f 73 6f 66 74 77 61 72 65 75 70 64 61 74 65 72 2e 62 6d 70 00 75 73 65 72 33 32 3a 3a 4c 6f 61 64 49 6d 61 67 65 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? [0-50] 4f 6e 43 6c 69 63 6b [0-0f] 49 6e 73 74 61 6c 61 72 20 42 61 73 65 66 6c 61 73 68 } //1
		$a_01_1 = {2f 4f 46 46 45 52 4b 45 59 57 4f 52 44 3d 62 61 73 65 66 6c 61 73 68 22 20 22 2f 4f 46 46 45 52 55 52 4c 3d 68 74 74 70 3a 2f 2f 64 6c 64 2e 62 61 73 65 66 6c 61 73 68 2e 63 6f 6d 2f 50 72 6f 74 65 63 74 62 61 73 65 66 6c 61 73 68 53 65 74 75 70 2e 65 78 65 } //1 /OFFERKEYWORD=baseflash" "/OFFERURL=http://dld.baseflash.com/ProtectbaseflashSetup.exe
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
rule SoftwareBundler_Win32_Taliavit_2{
	meta:
		description = "SoftwareBundler:Win32/Taliavit,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 06 00 00 "
		
	strings :
		$a_03_0 = {3d 4f 4b 53 50 26 [0-20] 26 70 6d 64 35 3d [0-90] 5c 62 61 73 65 66 6c 61 73 68 53 65 74 75 70 2e 65 78 65 } //2
		$a_01_1 = {2f 70 72 6f 74 65 63 74 62 61 73 65 66 6c 61 73 68 2f 50 72 6f 74 65 63 74 62 61 73 65 66 6c 61 73 68 53 65 74 75 70 2e 65 78 65 22 20 22 2f 4f 46 46 45 52 50 41 52 41 4d 53 3d } //2 /protectbaseflash/ProtectbaseflashSetup.exe" "/OFFERPARAMS=
		$a_01_2 = {76 69 74 6b 76 69 74 6b 2e 63 6f 6d 2f 78 6d 6c 73 74 61 74 69 63 2f 69 6e 73 74 61 6c 6c 65 72 73 2f } //1 vitkvitk.com/xmlstatic/installers/
		$a_01_3 = {53 4f 46 54 57 41 52 45 5c 50 72 6f 74 65 63 74 45 78 74 65 6e 73 69 6f 6e } //1 SOFTWARE\ProtectExtension
		$a_01_4 = {74 6b 44 65 63 72 69 70 74 2e 70 64 62 } //1 tkDecript.pdb
		$a_01_5 = {6f 6b 69 74 73 70 61 63 65 00 62 61 73 65 66 6c 61 73 68 00 } //1 歯瑩灳捡e慢敳汦獡h
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=5
 
}