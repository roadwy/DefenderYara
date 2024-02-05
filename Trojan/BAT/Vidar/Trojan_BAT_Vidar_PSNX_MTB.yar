
rule Trojan_BAT_Vidar_PSNX_MTB{
	meta:
		description = "Trojan:BAT/Vidar.PSNX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {28 07 00 00 0a 73 b9 02 00 06 28 ba 02 00 06 75 01 00 00 1b 6f 08 00 00 0a 2a } //00 00 
	condition:
		any of ($a_*)
 
}