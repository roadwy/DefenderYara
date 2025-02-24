
rule Trojan_BAT_AsyncRAT_KAAC_MTB{
	meta:
		description = "Trojan:BAT/AsyncRAT.KAAC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {07 09 03 09 91 04 61 9c 09 17 d6 0d 09 08 31 f0 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}