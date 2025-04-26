
rule TrojanDownloader_Win32_GameHack_ABB_MTB{
	meta:
		description = "TrojanDownloader:Win32/GameHack.ABB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 3a 2f 2f 62 72 75 68 2e 67 61 6d 65 73 2f 69 6e 74 65 72 6e 61 6c 2f 73 72 75 2f 53 52 55 5f 49 6e 74 65 72 6e 61 6c 5f 4c 6f 61 64 65 72 2e 65 78 65 } //1 http://bruh.games/internal/sru/SRU_Internal_Loader.exe
		$a_01_1 = {68 74 74 70 3a 2f 2f 62 72 75 68 2e 67 61 6d 65 73 2f 69 6e 74 65 72 6e 61 6c 2f 73 72 75 2f 53 52 55 5f 49 6e 74 65 72 6e 61 6c 2e 64 6c 6c } //1 http://bruh.games/internal/sru/SRU_Internal.dll
		$a_01_2 = {53 52 55 5f 49 6e 74 65 72 6e 61 6c 5f 4c 6f 61 64 65 72 2e 70 64 62 } //1 SRU_Internal_Loader.pdb
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}