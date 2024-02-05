
rule Trojan_AndroidOS_Iop_B_xp{
	meta:
		description = "Trojan:AndroidOS/Iop.B!xp,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_00_0 = {64 5f 32 50 68 69 50 35 73 74 72 5f 31 00 5f 5a 31 34 5f 5f 67 6e 75 5f 55 6e } //01 00 
		$a_00_1 = {00 12 00 08 00 af 00 00 00 3d 18 00 00 0a } //00 00 
	condition:
		any of ($a_*)
 
}