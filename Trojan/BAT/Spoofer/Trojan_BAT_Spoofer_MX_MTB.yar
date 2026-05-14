
rule Trojan_BAT_Spoofer_MX_MTB{
	meta:
		description = "Trojan:BAT/Spoofer.MX!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {11 05 06 6f 7b 00 00 0a 0b de 0c 11 05 2c 07 11 05 6f 0f 00 00 0a } //1
		$a_01_1 = {54 65 6d 70 20 53 70 6f 6f 66 } //1 Temp Spoof
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}