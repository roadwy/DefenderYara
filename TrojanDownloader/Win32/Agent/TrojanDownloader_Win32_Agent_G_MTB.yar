
rule TrojanDownloader_Win32_Agent_G_MTB{
	meta:
		description = "TrojanDownloader:Win32/Agent.G!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {25 ff 00 00 80 79 07 48 0d 00 ff ff ff 40 88 04 3e 46 81 fe 58 02 00 00 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}