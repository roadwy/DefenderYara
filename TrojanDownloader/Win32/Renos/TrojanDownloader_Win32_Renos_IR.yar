
rule TrojanDownloader_Win32_Renos_IR{
	meta:
		description = "TrojanDownloader:Win32/Renos.IR,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {b8 08 20 00 00 50 8d 85 ?? ?? ff ff 50 8b 85 ?? ?? ff ff 50 e8 } //1
		$a_01_1 = {81 f8 0d f0 ad de 0f 84 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}