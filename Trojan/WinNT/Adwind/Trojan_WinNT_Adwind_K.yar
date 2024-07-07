
rule Trojan_WinNT_Adwind_K{
	meta:
		description = "Trojan:WinNT/Adwind.K,SIGNATURE_TYPE_JAVAHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_01_0 = {01 00 05 6f 2d 78 5c 5f } //1
		$a_01_1 = {01 00 05 6d 5c 64 16 78 } //1
		$a_01_2 = {01 00 0b 67 65 74 50 61 73 73 77 6f 72 64 } //5
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*5) >=6
 
}