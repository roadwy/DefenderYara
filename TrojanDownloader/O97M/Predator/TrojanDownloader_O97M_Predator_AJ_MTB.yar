
rule TrojanDownloader_O97M_Predator_AJ_MTB{
	meta:
		description = "TrojanDownloader:O97M/Predator.AJ!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {6b 6b 28 33 2c 20 69 29 20 3d 20 52 65 70 6c 61 63 65 28 6b 6b 28 33 2c 20 69 29 2c 20 22 30 78 22 2c 20 22 26 68 22 29 } //1 kk(3, i) = Replace(kk(3, i), "0x", "&h")
		$a_01_1 = {44 65 62 75 67 2e 50 72 69 6e 74 20 22 31 36 3a 22 20 26 20 73 68 2e 43 65 6c 6c 73 28 6a 2c 20 32 29 20 26 20 22 3a 22 20 26 20 43 53 74 72 28 73 68 2e 43 65 6c 6c 73 28 6a 2c 20 33 29 29 20 26 20 22 20 20 22 20 26 20 6b 6b 28 33 2c 20 69 29 } //1 Debug.Print "16:" & sh.Cells(j, 2) & ":" & CStr(sh.Cells(j, 3)) & "  " & kk(3, i)
		$a_01_2 = {44 65 62 75 67 2e 50 72 69 6e 74 20 43 53 74 72 28 43 4c 6e 67 28 52 65 70 6c 61 63 65 28 6b 6b 2c 20 22 30 78 22 2c 20 22 26 68 22 29 29 29 } //1 Debug.Print CStr(CLng(Replace(kk, "0x", "&h")))
		$a_01_3 = {44 65 62 75 67 2e 50 72 69 6e 74 20 72 73 28 31 29 20 26 20 22 20 20 20 20 22 3b } //1 Debug.Print rs(1) & "    ";
		$a_01_4 = {4d 73 67 42 6f 78 20 28 22 3f 3f 3f 3f 3f 3f 3f 3f 3f 3f 3f 22 29 } //1 MsgBox ("???????????")
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}