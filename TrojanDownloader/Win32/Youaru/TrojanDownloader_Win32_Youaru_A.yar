
rule TrojanDownloader_Win32_Youaru_A{
	meta:
		description = "TrojanDownloader:Win32/Youaru.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {74 0a 80 f1 11 88 08 40 fe ca 75 f0 } //1
		$a_03_1 = {6a ff 6a 14 e8 ?? ?? ff ff fe cb 75 bc 8b 0e } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}