
rule Trojan_BAT_Redline_ASGE_MTB{
	meta:
		description = "Trojan:BAT/Redline.ASGE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {2b f9 02 08 02 08 91 03 20 be 00 00 00 d6 61 } //1
		$a_01_1 = {08 1b 5d 16 fe 01 0d 09 2c } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}