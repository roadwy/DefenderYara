
rule Trojan_Win32_TrojanDownloader_Delg_MTB{
	meta:
		description = "Trojan:Win32/TrojanDownloader.Delg!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {0c 00 00 40 0c 00 00 32 00 00 00 a0 0c 00 00 2c } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}