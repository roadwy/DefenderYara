
rule Trojan_BAT_Downloader_MRP_MTB{
	meta:
		description = "Trojan:BAT/Downloader.MRP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 05 00 00 "
		
	strings :
		$a_81_0 = {73 63 68 74 61 73 6b 73 20 2f 63 72 65 61 74 65 20 2f 73 63 20 6d 69 6e 75 74 65 20 2f 6d 6f 20 31 20 2f 74 6e 20 73 68 61 64 6f 77 64 65 76 20 2f 74 72 } //2 schtasks /create /sc minute /mo 1 /tn shadowdev /tr
		$a_81_1 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_81_2 = {70 72 30 74 33 5f 64 65 63 72 79 70 74 } //2 pr0t3_decrypt
		$a_81_3 = {67 65 74 5f 43 68 61 72 73 } //1 get_Chars
		$a_81_4 = {53 74 72 52 65 76 65 72 73 65 } //1 StrReverse
	condition:
		((#a_81_0  & 1)*2+(#a_81_1  & 1)*1+(#a_81_2  & 1)*2+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=7
 
}