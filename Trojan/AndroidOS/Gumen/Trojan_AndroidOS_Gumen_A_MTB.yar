
rule Trojan_AndroidOS_Gumen_A_MTB{
	meta:
		description = "Trojan:AndroidOS/Gumen.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {63 6f 6d 2f 74 65 73 74 61 62 63 2f 6d 79 74 65 73 74 } //1 com/testabc/mytest
		$a_01_1 = {26 65 78 65 63 75 74 69 6f 6e 3d 65 31 73 32 26 5f 65 76 65 6e 74 49 64 3d 73 75 62 6d 69 74 26 75 73 65 72 6e 61 6d 65 3d } //1 &execution=e1s2&_eventId=submit&username=
		$a_01_2 = {77 77 77 2e 53 55 50 45 52 37 38 39 2e 4e 45 54 } //1 www.SUPER789.NET
		$a_01_3 = {53 61 78 42 6f 6f 6b 50 61 72 73 65 72 } //1 SaxBookParser
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}