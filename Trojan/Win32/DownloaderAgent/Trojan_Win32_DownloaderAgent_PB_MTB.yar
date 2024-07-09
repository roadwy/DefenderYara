
rule Trojan_Win32_DownloaderAgent_PB_MTB{
	meta:
		description = "Trojan:Win32/DownloaderAgent.PB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 03 00 00 "
		
	strings :
		$a_00_0 = {8b 54 24 0c 59 8b 4c 24 04 8b c1 0b 4c 24 08 f7 d0 f7 d2 0b c2 23 c1 c3 } //5
		$a_00_1 = {8b 44 24 04 56 8b 74 24 0c 0f b6 08 8a 16 88 0e 88 10 5e c3 } //1
		$a_02_2 = {8b 45 f8 8b 75 14 0f be 04 30 50 ff 75 08 e8 ?? ?? ?? ff 83 c4 24 88 06 46 ff 4d 10 89 75 14 0f 85 ?? ff ff ff } //9
	condition:
		((#a_00_0  & 1)*5+(#a_00_1  & 1)*1+(#a_02_2  & 1)*9) >=15
 
}