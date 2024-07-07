
rule Trojan_BAT_AsyncRAT_PTFR_MTB{
	meta:
		description = "Trojan:BAT/AsyncRAT.PTFR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {6f 4a 00 00 0a 6f 4b 00 00 0a 72 cf 00 00 70 72 99 00 00 70 6f 4c 00 00 0a } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}