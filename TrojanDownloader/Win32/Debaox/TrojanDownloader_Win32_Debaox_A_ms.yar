
rule TrojanDownloader_Win32_Debaox_A_ms{
	meta:
		description = "TrojanDownloader:Win32/Debaox.A!ms,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {8d 14 18 8a 12 ?? ?? 80 f2 ?? 8d 0c 18 88 11 ?? ?? 40 3d ?? ?? ?? ?? 75 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}