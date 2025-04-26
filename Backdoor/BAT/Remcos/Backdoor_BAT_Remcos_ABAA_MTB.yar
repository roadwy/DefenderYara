
rule Backdoor_BAT_Remcos_ABAA_MTB{
	meta:
		description = "Backdoor:BAT/Remcos.ABAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {06 8e 69 17 59 0d 2b 0e 07 08 06 09 91 9c 08 17 58 0c 09 17 59 0d 09 16 2f ee } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}