
rule Trojan_MacOS_GetShell_D{
	meta:
		description = "Trojan:MacOS/GetShell.D,SIGNATURE_TYPE_MACHOHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_00_0 = {68 78 1f 00 00 68 2a 1f 00 00 68 6e 1f 00 00 68 55 1f 00 00 68 51 1f 00 00 68 f1 1e 00 00 68 13 1f 00 00 68 3d 1f 00 00 } //1
	condition:
		((#a_00_0  & 1)*1) >=1
 
}