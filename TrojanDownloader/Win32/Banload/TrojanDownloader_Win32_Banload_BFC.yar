
rule TrojanDownloader_Win32_Banload_BFC{
	meta:
		description = "TrojanDownloader:Win32/Banload.BFC,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 08 00 00 "
		
	strings :
		$a_01_0 = {00 44 49 2e 65 78 65 } //1
		$a_03_1 = {5c 61 4b 33 31 4d 41 53 54 45 52 30 ?? 2e 65 78 65 } //1
		$a_01_2 = {5c 55 50 54 6f 6f 6c 73 2e 65 78 65 } //1 \UPTools.exe
		$a_01_3 = {33 44 35 36 42 35 42 32 41 34 44 32 31 30 37 43 39 35 46 36 31 36 37 32 38 33 38 45 45 36 36 33 39 38 44 39 35 34 41 34 44 39 35 39 41 38 } //1 3D56B5B2A4D2107C95F61672838EE66398D954A4D959A8
		$a_01_4 = {2f 69 6e 73 74 61 6c 6c 20 2f 73 69 6c 65 6e 74 } //1 /install /silent
		$a_01_5 = {5c 6a 69 6d 67 6f 2e 64 61 74 } //1 \jimgo.dat
		$a_01_6 = {53 66 32 2e 64 6c 6c } //1 Sf2.dll
		$a_01_7 = {73 6e 78 68 6b 2e 64 6c 6c } //1 snxhk.dll
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=6
 
}