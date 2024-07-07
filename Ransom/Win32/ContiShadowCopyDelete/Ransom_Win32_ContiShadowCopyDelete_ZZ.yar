
rule Ransom_Win32_ContiShadowCopyDelete_ZZ{
	meta:
		description = "Ransom:Win32/ContiShadowCopyDelete.ZZ,SIGNATURE_TYPE_CMDHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_00_0 = {63 00 6d 00 64 00 2e 00 65 00 78 00 65 00 } //1 cmd.exe
		$a_00_1 = {57 00 4d 00 49 00 43 00 2e 00 65 00 78 00 65 00 } //1 WMIC.exe
		$a_00_2 = {77 00 68 00 65 00 72 00 65 00 } //1 where
		$a_00_3 = {49 00 44 00 3d 00 } //1 ID=
		$a_00_4 = {73 00 68 00 61 00 64 00 6f 00 77 00 63 00 6f 00 70 00 79 00 } //1 shadowcopy
		$a_00_5 = {64 00 65 00 6c 00 65 00 74 00 65 00 } //1 delete
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1) >=6
 
}