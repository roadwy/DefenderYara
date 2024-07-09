
rule TrojanDownloader_Win32_Amadey_PACK_MTB{
	meta:
		description = "TrojanDownloader:Win32/Amadey.PACK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {33 d2 32 cb 23 d2 d0 c1 f6 d1 66 c1 ea ec 13 d2 8d 94 d2 ?? ?? ?? ?? fe c1 52 80 f1 03 80 c2 86 32 d9 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}