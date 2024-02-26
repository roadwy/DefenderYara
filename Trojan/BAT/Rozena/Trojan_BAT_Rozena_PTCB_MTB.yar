
rule Trojan_BAT_Rozena_PTCB_MTB{
	meta:
		description = "Trojan:BAT/Rozena.PTCB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {07 6f 0c 00 00 0a 26 07 6f 0d 00 00 0a 02 6f 0e 00 00 0a 07 6f 0d 00 00 0a 6f 0f 00 00 0a } //00 00 
	condition:
		any of ($a_*)
 
}