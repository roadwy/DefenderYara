
rule TrojanDownloader_Win64_Rugmi_HNAD_MTB{
	meta:
		description = "TrojanDownloader:Win64/Rugmi.HNAD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 03 00 00 "
		
	strings :
		$a_01_0 = {90 55 48 83 ec 30 48 8d 6c 24 20 48 89 4d 20 48 89 55 28 44 89 45 30 48 8b 45 20 48 89 45 08 8b 45 30 89 45 00 6a ff 58 03 45 30 89 45 30 8b 45 00 85 c0 74 25 48 8b 45 28 48 8b 55 20 0f be 00 88 02 6a 01 58 48 03 45 20 48 89 45 20 6a 01 58 48 03 45 28 48 89 45 28 eb c5 } //10
		$a_03_1 = {33 c0 33 d2 48 [0-ff] [0-ff] ff d0 [0-ff] [0-ff] 63 ?? 3c } //1
		$a_03_2 = {33 c0 33 d2 48 [0-ff] [0-ff] 63 ?? 3c [0-ff] [0-ff] ff d0 } //1
	condition:
		((#a_01_0  & 1)*10+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=11
 
}