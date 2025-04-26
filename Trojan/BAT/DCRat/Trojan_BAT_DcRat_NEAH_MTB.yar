
rule Trojan_BAT_DcRat_NEAH_MTB{
	meta:
		description = "Trojan:BAT/DcRat.NEAH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {00 28 1b 00 00 06 0a 28 12 00 00 0a 06 6f 13 00 00 0a 28 14 00 00 0a 28 0f 00 00 06 0b dd 03 00 00 00 26 de db 07 2a } //10
	condition:
		((#a_01_0  & 1)*10) >=10
 
}