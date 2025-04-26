
rule SoftwareBundler_Win32_LinkPadBundle{
	meta:
		description = "SoftwareBundler:Win32/LinkPadBundle,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_80_0 = {50 72 6f 64 75 63 74 20 69 6e 66 6f 72 6d 61 74 69 6f 6e 20 69 73 20 6d 69 73 73 69 6e 67 2e 20 44 6f 20 6e 6f 74 20 63 68 61 6e 67 65 20 74 68 65 20 66 69 6c 65 6e 61 6d 65 2e } //Product information is missing. Do not change the filename.  2
		$a_80_1 = {00 5c 6c 69 6e 6b 2e 74 78 74 } //  2
		$a_80_2 = {68 72 65 74 75 72 6e 74 6f 69 6e 73 74 61 6c 6c 65 72 20 68 65 78 74 72 61 73 3d 69 64 3a } //hreturntoinstaller hextras=id:  1
		$a_80_3 = {47 65 6e 65 72 69 63 53 65 74 75 70 2e 65 78 65 } //GenericSetup.exe  1
		$a_80_4 = {74 68 69 73 3a 2f 2f 61 70 70 2f 2a } //this://app/*  1
	condition:
		((#a_80_0  & 1)*2+(#a_80_1  & 1)*2+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1) >=5
 
}