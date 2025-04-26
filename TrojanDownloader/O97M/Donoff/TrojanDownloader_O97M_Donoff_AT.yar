
rule TrojanDownloader_O97M_Donoff_AT{
	meta:
		description = "TrojanDownloader:O97M/Donoff.AT,SIGNATURE_TYPE_MACROHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_00_0 = {74 68 69 72 64 20 3d 20 28 74 68 69 72 64 20 2b 20 66 69 72 73 74 28 74 68 69 72 64 29 20 2b 20 31 29 20 4d 6f 64 20 32 35 36 } //1 third = (third + first(third) + 1) Mod 256
		$a_00_1 = {58 6f 72 20 66 69 72 73 74 28 54 65 6d 70 20 2b 20 66 69 72 73 74 28 28 74 68 69 72 64 20 2b 20 66 69 72 73 74 28 74 68 69 72 64 29 29 20 4d 6f 64 } //1 Xor first(Temp + first((third + first(third)) Mod
		$a_00_2 = {53 65 74 20 57 73 68 53 68 65 6c 6c 20 3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 } //1 Set WshShell = CreateObject(
		$a_00_3 = {3d 20 57 73 68 53 68 65 6c 6c 2e 45 78 70 61 6e 64 45 6e 76 69 72 6f 6e 6d 65 6e 74 53 74 72 69 6e 67 73 28 } //1 = WshShell.ExpandEnvironmentStrings(
		$a_00_4 = {73 2e 4d 6f 64 65 20 3d 20 33 0d 0a 73 2e 54 79 70 65 20 3d 20 32 0d 0a 73 2e 4f 70 65 6e 0d 0a } //1
		$a_00_5 = {43 61 6c 6c 20 73 2e 53 61 76 65 54 6f 46 69 6c 65 28 } //1 Call s.SaveToFile(
		$a_00_6 = {57 73 68 53 68 65 6c 6c 2e 52 75 6e } //1 WshShell.Run
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1) >=7
 
}