
rule TrojanDownloader_Win32_Renos_MD{
	meta:
		description = "TrojanDownloader:Win32/Renos.MD,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {78 39 63 38 37 76 63 78 39 38 37 76 39 38 63 78 37 76 2e 70 68 70 3f 69 6e 69 3d } //2 x9c87vcx987v98cx7v.php?ini=
		$a_01_1 = {70 68 70 3f 69 6e 69 3d 76 32 32 4d 6d 54 44 68 } //1 php?ini=v22MmTDh
		$a_01_2 = {50 4f 53 54 20 2f 78 39 63 38 37 76 63 78 } //1 POST /x9c87vcx
		$a_01_3 = {55 73 65 72 2d 41 67 65 6e 74 3a 20 4d 6f 7a 69 6c 6c 61 2f 36 2e 30 20 28 57 69 6e 64 6f 77 73 3b 20 77 67 65 74 20 33 2e 30 29 } //1 User-Agent: Mozilla/6.0 (Windows; wget 3.0)
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}