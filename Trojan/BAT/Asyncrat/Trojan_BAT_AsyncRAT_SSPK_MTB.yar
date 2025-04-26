
rule Trojan_BAT_AsyncRAT_SSPK_MTB{
	meta:
		description = "Trojan:BAT/AsyncRAT.SSPK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 01 00 00 "
		
	strings :
		$a_01_0 = {63 d1 13 11 11 1e 11 09 91 13 21 11 1e 11 09 11 22 11 21 61 19 11 1c 58 61 11 2f 61 d2 9c } //3
	condition:
		((#a_01_0  & 1)*3) >=3
 
}