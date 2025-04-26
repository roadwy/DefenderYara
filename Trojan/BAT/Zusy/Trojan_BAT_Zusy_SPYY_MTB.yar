
rule Trojan_BAT_Zusy_SPYY_MTB{
	meta:
		description = "Trojan:BAT/Zusy.SPYY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {06 08 06 6f ?? ?? ?? 0a 5d 6f ?? ?? ?? 0a 05 58 0d 07 02 08 6f ?? ?? ?? 0a 09 61 d1 6f ?? ?? ?? 0a 26 08 17 58 0c } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}