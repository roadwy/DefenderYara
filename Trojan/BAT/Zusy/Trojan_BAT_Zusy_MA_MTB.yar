
rule Trojan_BAT_Zusy_MA_MTB{
	meta:
		description = "Trojan:BAT/Zusy.MA!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {fe 0c 00 00 7e 01 00 00 04 73 23 00 00 0a fe 0c 02 00 6f 24 00 00 0a } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}