
rule Trojan_BAT_Zilla_PTDV_MTB{
	meta:
		description = "Trojan:BAT/Zilla.PTDV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {0a 16 0b 2b 30 02 07 91 28 ?? 00 00 0a 0c 08 20 80 00 00 00 32 0a 08 20 80 00 00 00 59 0c 2b 08 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}