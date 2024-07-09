
rule Trojan_BAT_RedLine_RDDX_MTB{
	meta:
		description = "Trojan:BAT/RedLine.RDDX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {06 07 1f 0a 5d 91 61 d2 81 ?? ?? ?? ?? 07 17 58 0b 07 03 8e 69 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}