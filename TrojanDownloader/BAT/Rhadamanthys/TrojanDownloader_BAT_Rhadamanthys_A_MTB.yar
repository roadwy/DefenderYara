
rule TrojanDownloader_BAT_Rhadamanthys_A_MTB{
	meta:
		description = "TrojanDownloader:BAT/Rhadamanthys.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_03_0 = {09 08 11 04 08 8e 69 5d 91 07 11 04 91 61 d2 6f 90 01 01 00 00 0a 11 04 17 58 90 00 } //2
		$a_01_1 = {47 65 74 54 79 70 65 } //1 GetType
		$a_01_2 = {54 6f 41 72 72 61 79 } //1 ToArray
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=4
 
}