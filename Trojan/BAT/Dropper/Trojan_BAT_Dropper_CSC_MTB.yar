
rule Trojan_BAT_Dropper_CSC_MTB{
	meta:
		description = "Trojan:BAT/Dropper.CSC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {02 07 91 03 07 91 fe 01 16 fe 01 0c 08 2c 02 16 0a 00 07 17 58 0b 07 02 8e 69 fe 04 } //10
	condition:
		((#a_01_0  & 1)*10) >=10
 
}