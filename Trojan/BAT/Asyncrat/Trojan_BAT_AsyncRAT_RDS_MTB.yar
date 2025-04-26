
rule Trojan_BAT_AsyncRAT_RDS_MTB{
	meta:
		description = "Trojan:BAT/AsyncRAT.RDS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 04 6f 1c 00 00 0a 5d 28 ?? ?? ?? ?? 61 d2 9c } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}