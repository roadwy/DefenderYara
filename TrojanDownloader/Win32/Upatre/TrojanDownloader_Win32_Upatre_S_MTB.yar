
rule TrojanDownloader_Win32_Upatre_S_MTB{
	meta:
		description = "TrojanDownloader:Win32/Upatre.S!MTB,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {4b 00 69 00 6c 00 69 00 6d 00 61 00 6e 00 6d 00 65 00 6e 00 } //1 Kilimanmen
		$a_01_1 = {48 00 6f 00 72 00 61 00 70 00 70 00 6c 00 69 00 73 00 74 00 } //1 Horapplist
		$a_01_2 = {48 00 6f 00 6b 00 65 00 75 00 6a 00 } //1 Hokeuj
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}