
rule HackTool_Linux_Turla_HA{
	meta:
		description = "HackTool:Linux/Turla.HA,SIGNATURE_TYPE_CMDHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_00_0 = {74 00 61 00 72 00 } //01 00  tar
		$a_00_1 = {65 00 65 00 65 00 2e 00 74 00 61 00 72 00 } //01 00  eee.tar
		$a_00_2 = {64 00 74 00 32 00 35 00 } //01 00  dt25
		$a_00_3 = {75 00 66 00 73 00 72 00 } //01 00  ufsr
		$a_00_4 = {73 00 63 00 20 00 75 00 78 00 } //00 00  sc ux
	condition:
		any of ($a_*)
 
}