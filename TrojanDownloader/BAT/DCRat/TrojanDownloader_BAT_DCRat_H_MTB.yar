
rule TrojanDownloader_BAT_DCRat_H_MTB{
	meta:
		description = "TrojanDownloader:BAT/DCRat.H!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 04 00 00 "
		
	strings :
		$a_03_0 = {0a 25 16 6f ?? 00 00 0a 74 ?? 00 00 01 [0-02] 25 [0-02] 72 ?? 00 00 70 6f ?? 00 00 0a 72 ?? 00 00 70 6f ?? 00 00 0a 6f ?? 00 00 0a 25 17 6f ?? 00 00 0a 75 ?? 00 00 01 [0-02] 25 d0 ?? 00 00 01 28 ?? 00 00 0a [0-02] 28 ?? 00 00 06 74 ?? 00 00 01 6f ?? 00 00 0a 25 18 6f } //2
		$a_03_1 = {8e 69 5d 91 03 [0-02] 91 61 d2 9c } //2
		$a_01_2 = {67 65 74 5f 41 53 43 49 49 } //1 get_ASCII
		$a_01_3 = {47 65 74 42 79 74 65 73 } //1 GetBytes
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=6
 
}