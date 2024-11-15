
rule TrojanDownloader_Win32_Phorpiex_B_MTB{
	meta:
		description = "TrojanDownloader:Win32/Phorpiex.B!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 45 08 03 45 ?? 0f be 08 f7 d1 8b 55 ?? 03 55 ?? 88 0a } //2
		$a_03_1 = {8b 4d f0 0f be 54 0d ?? 8b 45 ?? 03 45 ?? 0f be 08 33 ca 8b 55 ?? 03 55 ?? 88 0a } //4
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*4) >=6
 
}