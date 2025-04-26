
rule TrojanDownloader_Win32_Whinetroe_A{
	meta:
		description = "TrojanDownloader:Win32/Whinetroe.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b 48 0c 2b 48 14 8d 04 39 8a 4d d4 30 08 47 6a 02 58 01 45 e0 e9 } //1
		$a_00_1 = {4d 53 48 54 4d 4c 44 45 2e 44 4c 4c 00 44 6c 6c } //1 卍呈䱍䕄䐮䱌䐀汬
	condition:
		((#a_01_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}