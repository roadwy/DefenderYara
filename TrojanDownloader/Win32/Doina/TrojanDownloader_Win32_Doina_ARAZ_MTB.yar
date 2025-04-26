
rule TrojanDownloader_Win32_Doina_ARAZ_MTB{
	meta:
		description = "TrojanDownloader:Win32/Doina.ARAZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {0f b6 d0 8a 92 08 30 40 00 32 91 1b 30 40 00 fe c0 88 54 0d b0 41 3c 13 76 02 32 c0 4e 75 e1 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}