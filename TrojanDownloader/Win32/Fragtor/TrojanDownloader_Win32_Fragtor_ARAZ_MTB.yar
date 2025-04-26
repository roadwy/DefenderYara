
rule TrojanDownloader_Win32_Fragtor_ARAZ_MTB{
	meta:
		description = "TrojanDownloader:Win32/Fragtor.ARAZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 55 08 03 55 fc 0f be 02 33 45 0c 8b 4d 08 03 4d fc 88 01 eb d2 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}