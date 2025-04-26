
rule TrojanDownloader_Win32_Bucriv_A{
	meta:
		description = "TrojanDownloader:Win32/Bucriv.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {31 7c 25 73 7c 25 64 7c 25 73 7c 25 73 7c 25 73 7c 25 73 } //1 1|%s|%d|%s|%s|%s|%s
		$a_03_1 = {04 53 0f 85 90 09 0b 00 80 (3e|3f) 41 0f 85 ?? ?? ?? ?? 80 (|) 7e 7f } //1
		$a_01_2 = {56 68 00 00 00 80 56 56 8d 85 00 fe ff ff 50 57 ff 15 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}