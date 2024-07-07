
rule Worm_Win32_Irenegin_A{
	meta:
		description = "Worm:Win32/Irenegin.A,SIGNATURE_TYPE_PEHSTR_EXT,22 00 21 00 08 00 00 "
		
	strings :
		$a_00_0 = {61 74 74 72 69 62 20 2b 68 20 61 75 74 6f 72 75 6e 2e 69 6e 66 } //10 attrib +h autorun.inf
		$a_02_1 = {53 68 65 6c 6c 45 78 65 63 75 74 65 3d 90 02 08 2e 65 78 65 90 00 } //10
		$a_00_2 = {4e 65 74 53 68 61 72 65 41 64 64 } //5 NetShareAdd
		$a_00_3 = {47 65 74 44 72 69 76 65 54 79 70 65 41 } //5 GetDriveTypeA
		$a_00_4 = {46 69 65 73 74 61 73 } //1 Fiestas
		$a_00_5 = {5b 41 75 74 6f 52 75 6e 5d } //1 [AutoRun]
		$a_00_6 = {4d 65 64 69 61 50 61 74 68 } //1 MediaPath
		$a_00_7 = {53 4f 46 54 57 41 52 45 5c 42 6f 72 6c 61 6e 64 5c 44 65 6c 70 68 69 5c 52 54 4c } //1 SOFTWARE\Borland\Delphi\RTL
	condition:
		((#a_00_0  & 1)*10+(#a_02_1  & 1)*10+(#a_00_2  & 1)*5+(#a_00_3  & 1)*5+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1+(#a_00_7  & 1)*1) >=33
 
}