
rule TrojanDownloader_Win32_RaccoonStealerv2_A_MTB{
	meta:
		description = "TrojanDownloader:Win32/RaccoonStealerv2.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_03_0 = {31 14 30 83 c0 90 01 01 3b c1 90 00 } //2
		$a_03_1 = {31 34 11 83 c1 90 01 01 3b c8 90 00 } //2
		$a_03_2 = {30 04 32 8d 41 90 01 01 33 c9 42 90 00 } //2
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2+(#a_03_2  & 1)*2) >=6
 
}