
rule TrojanDownloader_Win32_Rugmi_HNAG_MTB{
	meta:
		description = "TrojanDownloader:Win32/Rugmi.HNAG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b d0 0f be 0b 03 d9 03 f3 8b 42 3c 8b 6b 04 8b 5b 08 8b 7c 10 2c 8d 44 24 } //10
		$a_01_1 = {8d 40 04 83 e9 01 } //1
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*1) >=11
 
}