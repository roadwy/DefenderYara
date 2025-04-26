
rule TrojanDownloader_Win32_Banload_BGB{
	meta:
		description = "TrojanDownloader:Win32/Banload.BGB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {41 5f 5f 5f 72 5f 71 5f 5f 75 49 5f 5f 43 6f 5f 5f 70 49 5f 61 } //1 A___r_q__uI__Co__pI_a
		$a_01_1 = {50 5f 5f 75 78 61 5f 5f 61 72 71 75 69 5f 5f 76 6f 73 } //1 P__uxa__arqui__vos
		$a_01_2 = {2e 00 2e 00 2e 00 49 00 6e 00 74 00 65 00 6e 00 74 00 61 00 6e 00 64 00 6f 00 20 00 63 00 6f 00 6e 00 65 00 63 00 74 00 61 00 72 00 } //1 ...Intentando conectar
		$a_01_3 = {63 00 6f 00 6d 00 70 00 72 00 75 00 65 00 62 00 65 00 20 00 6c 00 61 00 20 00 63 00 6f 00 6e 00 65 00 78 00 69 00 } //1 compruebe la conexi
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}