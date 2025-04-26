
rule Trojan_BAT_AsyncRAT_ARAX_MTB{
	meta:
		description = "Trojan:BAT/AsyncRAT.ARAX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {00 06 08 03 08 91 04 08 04 8e 69 5d 91 61 07 08 07 8e 69 5d 91 61 28 ?? ?? ?? 0a 9c 00 08 17 58 0c 08 03 8e 69 fe 04 0d 09 2d d5 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}