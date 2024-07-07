
rule Trojan_MacOS_GetShell_E{
	meta:
		description = "Trojan:MacOS/GetShell.E,SIGNATURE_TYPE_MACHOHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_00_0 = {68 78 1f 00 00 68 74 1f 00 00 68 63 1e 00 00 68 9d 1e 00 00 68 e2 1e 00 00 68 f2 1e 00 00 68 ea 1e 00 00 68 ee 1e 00 00 } //1
	condition:
		((#a_00_0  & 1)*1) >=1
 
}