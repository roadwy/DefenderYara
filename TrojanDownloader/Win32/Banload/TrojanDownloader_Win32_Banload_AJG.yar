
rule TrojanDownloader_Win32_Banload_AJG{
	meta:
		description = "TrojanDownloader:Win32/Banload.AJG,SIGNATURE_TYPE_PEHSTR_EXT,04 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {70 6a 63 74 31 2e 6a 70 67 } //1 pjct1.jpg
		$a_01_1 = {6a 61 76 61 2e 6a 70 67 } //1 java.jpg
		$a_01_2 = {52 75 6e 22 20 2f 76 20 70 6a 63 74 31 20 2f 64 } //1 Run" /v pjct1 /d
		$a_01_3 = {63 68 61 76 65 3d 78 63 68 61 76 65 26 } //1 chave=xchave&
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}