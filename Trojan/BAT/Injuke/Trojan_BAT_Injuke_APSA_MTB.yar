
rule Trojan_BAT_Injuke_APSA_MTB{
	meta:
		description = "Trojan:BAT/Injuke.APSA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 02 00 00 "
		
	strings :
		$a_01_0 = {07 11 06 09 11 06 91 06 11 06 91 61 d2 9c 11 06 17 58 13 06 11 06 09 8e 69 32 e5 } //5
		$a_01_1 = {11 04 08 59 02 8e 69 58 02 8e 69 5d 13 05 09 11 05 02 11 04 91 9c 11 04 17 58 13 04 11 04 02 8e 69 32 dd } //2
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*2) >=7
 
}