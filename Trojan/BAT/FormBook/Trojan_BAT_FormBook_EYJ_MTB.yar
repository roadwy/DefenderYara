
rule Trojan_BAT_FormBook_EYJ_MTB{
	meta:
		description = "Trojan:BAT/FormBook.EYJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {59 00 55 00 47 00 35 00 34 00 47 00 35 00 45 00 41 00 } //1 YUG54G5EA
		$a_01_1 = {00 4d 65 73 73 61 67 65 00 50 72 6f 70 65 72 74 69 65 73 00 } //1 䴀獥慳敧倀潲数瑲敩s
		$a_01_2 = {43 6f 6d 70 72 65 73 73 69 6f 6e 4d 6f 64 65 } //1 CompressionMode
		$a_01_3 = {47 5a 69 70 53 74 72 65 61 6d } //1 GZipStream
		$a_01_4 = {44 65 62 75 67 67 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //1 DebuggableAttribute
		$a_01_5 = {44 65 62 75 67 67 69 6e 67 4d 6f 64 65 73 } //1 DebuggingModes
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}