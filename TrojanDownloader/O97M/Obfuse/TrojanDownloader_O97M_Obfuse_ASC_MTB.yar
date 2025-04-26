
rule TrojanDownloader_O97M_Obfuse_ASC_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.ASC!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_01_0 = {50 72 69 76 61 74 65 20 44 65 63 6c 61 72 65 20 46 75 6e 63 74 69 6f 6e 20 45 32 67 7a 32 58 6b 79 75 64 64 20 4c 69 62 20 22 75 73 65 72 33 32 2e 64 6c 6c 22 20 41 6c 69 61 73 20 22 50 6f 73 74 4d 65 73 73 61 67 65 41 22 20 } //1 Private Declare Function E2gz2Xkyudd Lib "user32.dll" Alias "PostMessageA" 
		$a_01_1 = {46 75 6e 63 74 69 6f 6e 20 50 32 7a 7a 6e 38 77 6f 38 30 47 33 72 28 29 } //1 Function P2zzn8wo80G3r()
		$a_01_2 = {50 32 7a 7a 6e 38 77 6f 38 30 47 33 72 20 3d 20 4a 6f 69 6e 28 41 72 72 61 79 28 43 68 72 57 28 43 4c 6e 67 28 28 4e 6f 74 20 2d 34 37 29 29 29 20 26 20 43 68 72 57 28 43 4c 6e 67 28 28 } //1 P2zzn8wo80G3r = Join(Array(ChrW(CLng((Not -47))) & ChrW(CLng((
		$a_01_3 = {3d 20 43 68 72 28 43 4c 6e 67 28 28 41 73 63 57 28 22 77 22 29 29 29 29 20 5f } //1 = Chr(CLng((AscW("w")))) _
		$a_01_4 = {53 65 74 20 49 79 48 6b 6c 78 30 59 20 3d 20 47 65 74 4f 62 6a 65 63 74 28 57 76 78 42 5f 68 70 63 37 29 2e 53 70 61 77 6e 49 6e 73 74 61 6e 63 65 5f } //1 Set IyHklx0Y = GetObject(WvxB_hpc7).SpawnInstance_
		$a_01_5 = {2e 53 68 6f 77 57 69 6e 64 6f 77 20 3d 20 43 4c 6e 67 28 28 30 2e } //1 .ShowWindow = CLng((0.
		$a_01_6 = {41 73 63 28 4c 65 66 74 24 28 4d 69 64 24 28 56 44 44 39 52 5f 51 6b 6c 5f 49 51 6c 5f 30 49 75 51 2c 20 54 39 68 62 49 46 52 62 6b 79 29 2c } //1 Asc(Left$(Mid$(VDD9R_Qkl_IQl_0IuQ, T9hbIFRbky),
		$a_01_7 = {26 20 43 68 72 57 28 43 4c 6e 67 28 28 41 73 63 28 22 4d 22 29 29 29 29 20 26 20 43 68 72 28 43 4c 6e 67 28 28 41 73 63 57 28 22 69 22 29 29 29 29 20 26 } //1 & ChrW(CLng((Asc("M")))) & Chr(CLng((AscW("i")))) &
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=8
 
}