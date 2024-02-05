
rule Trojan_Win16_ShellHide_D{
	meta:
		description = "Trojan:Win16/ShellHide.D,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {22 25 38 33 37 34 33 32 39 38 37 66 68 66 39 38 37 72 38 64 73 63 39 38 25 6d 25 38 33 37 34 33 32 39 38 37 66 68 66 39 38 37 72 38 64 73 63 39 38 25 } //00 00 
	condition:
		any of ($a_*)
 
}