
rule Trojan_BAT_Convagent_PSVQ_MTB{
	meta:
		description = "Trojan:BAT/Convagent.PSVQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {02 7b 31 00 00 04 07 6f ?? 00 00 0a 1f ec 16 73 3d 00 00 06 6f ?? 00 00 06 2b 4f 02 7b 31 00 00 04 07 6f ?? 00 00 0a 1f 14 16 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}