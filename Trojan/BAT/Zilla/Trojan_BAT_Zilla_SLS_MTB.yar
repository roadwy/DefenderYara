
rule Trojan_BAT_Zilla_SLS_MTB{
	meta:
		description = "Trojan:BAT/Zilla.SLS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {72 2d 02 00 70 0a 72 ?? ?? ?? 70 0b 73 0c 00 00 0a 0c 08 06 07 6f 0d 00 00 0a de 0a } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}