
rule Trojan_BAT_Zilla_KAU_MTB{
	meta:
		description = "Trojan:BAT/Zilla.KAU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {03 17 59 6a 58 0a 03 6a 06 03 6a 5b 5a 0b 07 73 ?? 00 00 0a 2a } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}