
rule TrojanDownloader_Win32_Banload_UG{
	meta:
		description = "TrojanDownloader:Win32/Banload.UG,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {2a 68 40 74 2a 40 74 70 3a 2a 2f 2a 2f } //1 *h@t*@tp:*/*/
		$a_01_1 = {53 2a 68 65 6c 6c 2a 7c 2a 33 32 2e 44 2a 40 4c 2a 40 4c } //1 S*hell*|*32.D*@L*@L
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}