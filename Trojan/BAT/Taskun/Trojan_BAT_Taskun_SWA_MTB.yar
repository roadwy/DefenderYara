
rule Trojan_BAT_Taskun_SWA_MTB{
	meta:
		description = "Trojan:BAT/Taskun.SWA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {11 0b 11 0c 94 13 0d 00 11 04 11 0d 19 5a 11 0d 18 63 59 6a 58 13 04 11 04 11 04 1b 62 11 04 19 63 60 61 13 04 00 11 0c 17 58 13 0c 11 0c 11 0b 8e 69 32 cc } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}