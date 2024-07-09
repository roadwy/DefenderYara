
rule Trojan_BAT_Rozena_CXJR_MTB{
	meta:
		description = "Trojan:BAT/Rozena.CXJR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {03 06 03 8e 69 5d 91 61 d2 81 ?? ?? ?? ?? 00 06 17 58 0a 06 02 8e 69 fe 04 0c 08 2d d5 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}