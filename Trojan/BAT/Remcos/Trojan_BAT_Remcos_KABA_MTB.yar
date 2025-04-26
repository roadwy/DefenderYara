
rule Trojan_BAT_Remcos_KABA_MTB{
	meta:
		description = "Trojan:BAT/Remcos.KABA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {19 59 91 08 09 08 8e 69 5d 1f 09 58 1f 0a 58 1f 13 59 1c 58 1c 59 91 61 06 09 20 11 02 00 00 58 20 10 02 00 00 59 06 8e 69 5d 1f 09 58 1f 0c 58 1f 15 59 1c 58 1c 59 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}