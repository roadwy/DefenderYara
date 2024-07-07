
rule Trojan_Win64_Dridex_ALE_MTB{
	meta:
		description = "Trojan:Win64/Dridex.ALE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,18 00 18 00 08 00 00 "
		
	strings :
		$a_80_0 = {66 70 72 6f 6c 67 37 36 } //fprolg76  3
		$a_80_1 = {73 64 6d 66 7c 65 72 2e 70 64 62 } //sdmf|er.pdb  3
		$a_80_2 = {72 61 69 73 69 6e 67 6e 35 38 37 } //raisingn587  3
		$a_80_3 = {61 69 6e 63 6c 75 64 69 6e 67 31 70 } //aincluding1p  3
		$a_80_4 = {53 48 50 61 74 68 50 72 65 70 61 72 65 46 6f 72 57 72 69 74 65 57 } //SHPathPrepareForWriteW  3
		$a_80_5 = {43 72 79 70 74 43 41 54 47 65 74 43 61 74 41 74 74 72 49 6e 66 6f } //CryptCATGetCatAttrInfo  3
		$a_80_6 = {6d 69 64 69 4f 75 74 43 61 63 68 65 50 61 74 63 68 65 73 } //midiOutCachePatches  3
		$a_80_7 = {53 43 61 72 64 52 65 6c 65 61 73 65 43 6f 6e 74 65 78 74 } //SCardReleaseContext  3
	condition:
		((#a_80_0  & 1)*3+(#a_80_1  & 1)*3+(#a_80_2  & 1)*3+(#a_80_3  & 1)*3+(#a_80_4  & 1)*3+(#a_80_5  & 1)*3+(#a_80_6  & 1)*3+(#a_80_7  & 1)*3) >=24
 
}