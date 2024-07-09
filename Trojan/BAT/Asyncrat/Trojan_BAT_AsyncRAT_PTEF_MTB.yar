
rule Trojan_BAT_AsyncRAT_PTEF_MTB{
	meta:
		description = "Trojan:BAT/AsyncRAT.PTEF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {38 ed fd ff ff 12 01 28 ?? 00 00 0a 28 ?? 03 00 06 13 0a } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}