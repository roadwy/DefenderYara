
rule TrojanDownloader_Win32_Chepvil_I{
	meta:
		description = "TrojanDownloader:Win32/Chepvil.I,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {85 db 75 25 31 db 43 80 bd f4 fb ff ff 4d 75 19 31 db 43 80 bd f5 fb ff ff 5a 75 0d } //1
		$a_01_1 = {6a 00 6a 00 68 52 08 00 00 ff 15 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}