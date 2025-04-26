
rule Trojan_BAT_Zilla_PTDK_MTB{
	meta:
		description = "Trojan:BAT/Zilla.PTDK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {12 0a e0 28 ?? 00 00 0a 6f 29 00 00 0a 13 06 02 16 9a 73 0d 00 00 06 13 0c } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}