
rule Trojan_BAT_Zusy_PTFH_MTB{
	meta:
		description = "Trojan:BAT/Zusy.PTFH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {6f 9c 00 00 0a 17 73 3c 00 00 0a 25 02 16 02 8e 69 6f 9d 00 00 0a } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}