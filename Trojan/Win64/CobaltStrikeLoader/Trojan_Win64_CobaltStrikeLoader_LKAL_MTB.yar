
rule Trojan_Win64_CobaltStrikeLoader_LKAL_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrikeLoader.LKAL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {4d 41 43 4f 53 58 5c 70 64 66 2e 70 64 66 } //1 MACOSX\pdf.pdf
		$a_01_1 = {75 00 70 00 64 00 61 00 74 00 65 00 73 00 61 00 6e 00 66 00 6f 00 72 00 2e 00 73 00 33 00 2d 00 75 00 73 00 2d 00 65 00 61 00 73 00 74 00 2d 00 31 00 2e 00 6f 00 73 00 73 00 66 00 69 00 6c 00 65 00 73 00 2e 00 63 00 6f 00 6d 00 2f 00 6a 00 61 00 76 00 61 00 4c 00 69 00 73 00 74 00 65 00 6e 00 } //1 updatesanfor.s3-us-east-1.ossfiles.com/javaListen
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}