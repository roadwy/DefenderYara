
rule Trojan_BAT_Injuke_PRAA_MTB{
	meta:
		description = "Trojan:BAT/Injuke.PRAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {07 09 18 6f ?? ?? 00 0a 1f 10 28 ?? ?? 00 0a 13 04 11 04 16 3f 08 00 00 00 08 11 04 6f ?? 00 00 0a 09 18 58 0d 09 07 6f ?? 00 00 0a 3f ?? ff ff ff 08 13 05 dd ?? 00 00 00 26 dd } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}