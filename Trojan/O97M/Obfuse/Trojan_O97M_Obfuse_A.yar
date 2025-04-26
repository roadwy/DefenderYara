
rule Trojan_O97M_Obfuse_A{
	meta:
		description = "Trojan:O97M/Obfuse.A,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {20 3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 53 74 72 52 65 76 65 72 73 65 28 } //1  = CreateObject(StrReverse(
		$a_00_1 = {20 26 20 53 74 72 52 65 76 65 72 73 65 28 53 74 72 52 65 76 65 72 73 65 28 53 74 72 52 65 76 65 72 73 65 28 53 74 72 52 65 76 65 72 73 65 28 } //1  & StrReverse(StrReverse(StrReverse(StrReverse(
		$a_00_2 = {20 3d 20 31 20 54 6f 20 4c 65 6e 28 } //1  = 1 To Len(
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}