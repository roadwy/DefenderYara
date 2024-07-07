
rule Trojan_BAT_Redline_GFQ_MTB{
	meta:
		description = "Trojan:BAT/Redline.GFQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {58 36 43 79 71 34 49 54 75 65 73 46 4c 73 6f 31 72 63 } //1 X6Cyq4ITuesFLso1rc
		$a_01_1 = {46 72 6f 6d 42 61 73 65 36 34 43 68 61 72 41 72 72 61 79 } //1 FromBase64CharArray
		$a_01_2 = {41 44 72 49 6b 70 7a 4d 61 34 67 72 44 34 52 72 55 68 } //1 ADrIkpzMa4grD4RrUh
		$a_01_3 = {49 6e 76 6f 6b 65 4d 65 6d 62 65 72 } //1 InvokeMember
		$a_01_4 = {64 58 52 59 66 77 59 47 35 } //1 dXRYfwYG5
		$a_01_5 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}