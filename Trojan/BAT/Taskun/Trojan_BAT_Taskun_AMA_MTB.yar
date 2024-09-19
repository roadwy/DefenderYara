
rule Trojan_BAT_Taskun_AMA_MTB{
	meta:
		description = "Trojan:BAT/Taskun.AMA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {04 18 fe 04 16 fe 01 0b 07 2c 0e 02 0f 01 28 ?? 00 00 0a 6f ?? 00 00 0a 00 04 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}