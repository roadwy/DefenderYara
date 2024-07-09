
rule TrojanDownloader_Win32_Tikoog_A_ms{
	meta:
		description = "TrojanDownloader:Win32/Tikoog.A!ms,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {83 c1 01 8b 55 ?? 8b 02 99 f7 f9 0f af 45 ?? ?? 45 ?? ?? 45 ?? ?? ?? 00 00 } //1
		$a_03_1 = {99 f7 f9 03 45 ?? 89 45 ?? eb cf } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}