
rule Trojan_Linux_MsfShellBin_E{
	meta:
		description = "Trojan:Linux/MsfShellBin.E,SIGNATURE_TYPE_ELFHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {31 db 53 43 53 6a 0a 89 e1 6a 66 58 cd 80 96 99 68 90 01 04 68 90 01 04 68 90 01 04 68 90 01 04 68 90 01 04 52 66 68 90 01 02 66 68 0a 00 89 e1 6a 1c 51 56 89 e1 43 43 6a 66 58 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}