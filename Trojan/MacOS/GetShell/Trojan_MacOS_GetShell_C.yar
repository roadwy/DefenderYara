
rule Trojan_MacOS_GetShell_C{
	meta:
		description = "Trojan:MacOS/GetShell.C,SIGNATURE_TYPE_MACHOHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_00_0 = {68 78 1f 00 00 68 74 1f 00 00 68 6c 1f 00 00 68 53 1f 00 00 68 4f 1f 00 00 68 4b 1f 00 00 68 47 1f 00 00 68 43 1f 00 00 } //1
	condition:
		((#a_00_0  & 1)*1) >=1
 
}