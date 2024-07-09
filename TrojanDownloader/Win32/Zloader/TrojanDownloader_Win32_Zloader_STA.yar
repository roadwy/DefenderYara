
rule TrojanDownloader_Win32_Zloader_STA{
	meta:
		description = "TrojanDownloader:Win32/Zloader.STA,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {55 8b ec 6a 0c 68 ?? ?? 00 10 68 ?? ?? 00 10 e8 } //1
		$a_01_1 = {8b 45 0c 0f be 0c 10 33 d9 8b 55 f8 03 55 fc 88 1a } //1
		$a_01_2 = {6c 6f 61 64 65 72 5f 78 6c 73 2e 64 6c 6c 00 49 6e 00 } //1 潬摡牥硟獬搮汬䤀n
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}