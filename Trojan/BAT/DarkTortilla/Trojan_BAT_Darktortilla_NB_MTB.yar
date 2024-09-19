
rule Trojan_BAT_Darktortilla_NB_MTB{
	meta:
		description = "Trojan:BAT/Darktortilla.NB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_01_0 = {02 1f 49 61 b4 0a 18 0d 2b b5 02 0a 18 0d 2b af } //5
		$a_01_1 = {26 16 0d 2b d0 03 1d 5d 16 fe 01 0b 07 } //5
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5) >=10
 
}