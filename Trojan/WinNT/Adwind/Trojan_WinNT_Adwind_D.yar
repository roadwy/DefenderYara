
rule Trojan_WinNT_Adwind_D{
	meta:
		description = "Trojan:WinNT/Adwind.D,SIGNATURE_TYPE_JAVAHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {41 4c 53 4b 45 4f 50 51 4c 46 4b 4a 44 55 53 49 4b 53 4a 41 55 49 45 90 02 ff 6a 61 76 61 2f 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}