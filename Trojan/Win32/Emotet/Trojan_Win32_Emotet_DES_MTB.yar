
rule Trojan_Win32_Emotet_DES_MTB{
	meta:
		description = "Trojan:Win32/Emotet.DES!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 03 00 00 "
		
	strings :
		$a_02_0 = {6a 00 6a 01 6a 00 6a 00 8d 45 ?? 50 ff 55 ?? 85 c0 75 ?? 6a 08 6a 01 6a 00 6a 00 8d 4d 90 1b 00 51 ff 55 90 1b 01 85 c0 75 ?? 68 00 00 00 f0 6a 01 6a 00 6a 00 8d 55 90 1b 00 52 ff 55 } //1
		$a_01_1 = {72 00 63 00 4f 00 4f 00 6f 00 62 00 68 00 4b 00 6a 00 6e 00 52 00 4b 00 66 00 42 00 74 00 44 00 4a 00 78 00 42 00 53 00 54 00 72 00 6f 00 69 00 64 00 55 00 } //1 rcOOobhKjnRKfBtDJxBSTroidU
		$a_81_2 = {39 4d 6c 33 63 64 7b 70 48 23 65 7c 39 7a 33 59 40 6b 7b 47 6e 57 63 6e 6c 4a 71 79 4a 71 49 79 72 5a } //1 9Ml3cd{pH#e|9z3Y@k{GnWcnlJqyJqIyrZ
	condition:
		((#a_02_0  & 1)*1+(#a_01_1  & 1)*1+(#a_81_2  & 1)*1) >=1
 
}