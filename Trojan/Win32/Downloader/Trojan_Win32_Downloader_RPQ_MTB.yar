
rule Trojan_Win32_Downloader_RPQ_MTB{
	meta:
		description = "Trojan:Win32/Downloader.RPQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {0b 5d 00 3d a6 00 00 00 83 fb 75 e8 [0-10] 90 13 [0-20] 01 1c 38 [0-20] 90 13 [0-10] 81 ef [0-20] 90 13 [0-10] 81 c7 [0-10] 0f 8d } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}