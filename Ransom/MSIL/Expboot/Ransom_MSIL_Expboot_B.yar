
rule Ransom_MSIL_Expboot_B{
	meta:
		description = "Ransom:MSIL/Expboot.B,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_80_0 = {59 6f 75 72 20 46 69 6c 65 73 20 41 72 65 20 41 6c 6c 20 45 6e 63 72 79 70 74 65 64 21 } //Your Files Are All Encrypted!  01 00 
		$a_00_1 = {45 78 70 42 6f 6f 74 2e 65 78 65 } //00 00 
	condition:
		any of ($a_*)
 
}