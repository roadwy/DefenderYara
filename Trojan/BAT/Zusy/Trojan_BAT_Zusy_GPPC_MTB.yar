
rule Trojan_BAT_Zusy_GPPC_MTB{
	meta:
		description = "Trojan:BAT/Zusy.GPPC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_03_0 = {8d 07 00 00 01 25 16 03 1f 4d 6f ?? 00 00 0a d2 9c 25 17 03 1f 5a } //4
	condition:
		((#a_03_0  & 1)*4) >=4
 
}