
rule TrojanDownloader_Win32_Beebone_gen_D{
	meta:
		description = "TrojanDownloader:Win32/Beebone.gen!D,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {2d 00 31 00 33 00 39 00 36 00 36 00 34 00 33 00 33 00 36 00 32 00 41 00 64 00 6d 00 69 00 6e 00 69 00 73 00 74 00 72 00 61 00 74 00 6f 00 72 00 } //2 -1396643362Administrator
		$a_03_1 = {36 00 38 00 30 00 34 00 30 00 30 00 43 00 43 00 30 00 30 00 45 00 38 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 35 00 39 00 38 00 39 00 30 00 31 00 36 00 36 00 33 00 31 00 43 00 30 00 43 00 33 00 } //2
		$a_01_2 = {2f 00 63 00 20 00 74 00 61 00 73 00 6b 00 6c 00 69 00 73 00 74 00 26 00 26 00 64 00 65 00 6c 00 } //1 /c tasklist&&del
		$a_01_3 = {38 00 42 00 34 00 43 00 32 00 34 00 30 00 38 00 35 00 31 00 3c 00 50 00 41 00 54 00 43 00 48 00 31 00 3e 00 45 00 38 00 3c 00 50 00 41 00 54 00 43 00 48 00 32 00 3e 00 35 00 39 00 38 00 39 00 30 00 31 00 36 00 36 00 33 00 31 00 43 00 30 00 43 00 33 00 } //1 8B4C240851<PATCH1>E8<PATCH2>5989016631C0C3
	condition:
		((#a_01_0  & 1)*2+(#a_03_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}