
rule TrojanDownloader_Win32_Small_B_MTB{
	meta:
		description = "TrojanDownloader:Win32/Small.B!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {0f be c9 c1 e0 04 03 c1 8b c8 42 81 e1 00 00 00 f0 74 07 8b f1 c1 ee 18 33 c6 f7 d1 23 c1 8a 0a 84 c9 75 dc } //1
		$a_03_1 = {8b 45 fc 8b 14 87 03 d6 ?? ?? ?? ?? ?? 3b 45 08 74 11 ff 45 fc 8b 45 fc 3b 45 f8 72 e3 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}