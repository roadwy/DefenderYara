
rule Trojan_Linux_Pkexec_A{
	meta:
		description = "Trojan:Linux/Pkexec.A,SIGNATURE_TYPE_CMDHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_00_0 = {67 00 63 00 6f 00 6e 00 76 00 5f 00 70 00 61 00 74 00 68 00 3d 00 } //00 00 
	condition:
		any of ($a_*)
 
}