
rule TrojanDownloader_Win32_Chepvil_L{
	meta:
		description = "TrojanDownloader:Win32/Chepvil.L,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {85 db 75 25 31 db 43 80 bd d4 fb ff ff 4d 75 19 31 db 43 80 bd d5 fb ff ff 5a 75 0d c7 85 ?? ?? ?? ?? ?? ?? ?? ?? 31 db 43 8d 04 ?? 6a 00 } //1
		$a_02_1 = {32 44 39 01 88 84 ?? ?? ?? ?? ?? 8b 85 ?? ?? ?? ?? 80 bc ?? ?? ?? ?? ?? 2c } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}