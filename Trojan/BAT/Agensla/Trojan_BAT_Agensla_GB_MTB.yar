
rule Trojan_BAT_Agensla_GB_MTB{
	meta:
		description = "Trojan:BAT/Agensla.GB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_80_0 = {46 75 63 6b 69 6e 67 } //Fucking  01 00 
		$a_80_1 = {4d 6f 74 68 65 72 46 75 63 6b 65 72 42 69 74 63 68 } //MotherFuckerBitch  01 00 
		$a_80_2 = {44 6f 77 6e 6c 6f 61 64 53 74 72 69 6e 67 } //DownloadString  01 00 
		$a_80_3 = {6c 69 76 65 72 70 6f 6f 6c } //liverpool  00 00 
	condition:
		any of ($a_*)
 
}