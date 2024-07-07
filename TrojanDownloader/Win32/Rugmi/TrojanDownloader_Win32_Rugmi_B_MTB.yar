
rule TrojanDownloader_Win32_Rugmi_B_MTB{
	meta:
		description = "TrojanDownloader:Win32/Rugmi.B!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {31 0c 16 83 c2 90 01 01 39 c2 90 00 } //2
		$a_03_1 = {31 3c 03 83 c0 90 01 01 39 f0 90 00 } //2
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2) >=4
 
}