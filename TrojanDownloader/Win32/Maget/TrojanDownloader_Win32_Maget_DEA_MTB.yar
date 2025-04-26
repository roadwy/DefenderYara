
rule TrojanDownloader_Win32_Maget_DEA_MTB{
	meta:
		description = "TrojanDownloader:Win32/Maget.DEA!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {02 c2 0f b6 c0 89 44 24 10 8a 44 04 14 88 44 1c 14 8b 44 24 10 88 4c 04 14 8a 44 1c 14 02 c2 0f b6 c0 8a 44 04 14 32 04 3e 88 07 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}