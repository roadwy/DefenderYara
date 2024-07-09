
rule Ransom_Win32_Sodinokibi_SA{
	meta:
		description = "Ransom:Win32/Sodinokibi.SA,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 05 00 00 "
		
	strings :
		$a_80_0 = {53 4f 46 54 49 53 } //SOFTIS  1
		$a_80_1 = {4d 4f 44 4c 49 53 } //MODLIS  1
		$a_80_2 = {6d 70 73 76 63 2e 64 6c 6c } //mpsvc.dll  1
		$a_80_3 = {4d 73 4d 70 45 6e 67 2e 65 78 65 } //MsMpEng.exe  1
		$a_02_4 = {ba 88 55 0c 00 a3 ?? ?? ?? ?? ?? ?? e8 [0-20] ba d0 56 00 00 c7 ?? ?? ?? ?? ?? ?? e8 } //5
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_02_4  & 1)*5) >=7
 
}