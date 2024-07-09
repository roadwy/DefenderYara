
rule Trojan_BAT_Avemariarat_VN_MTB{
	meta:
		description = "Trojan:BAT/Avemariarat.VN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {91 07 61 08 11 ?? 91 61 b4 9c 1f ?? 2b ?? 90 09 06 00 09 11 ?? 02 11 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_BAT_Avemariarat_VN_MTB_2{
	meta:
		description = "Trojan:BAT/Avemariarat.VN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {03 09 18 6f ?? ?? ?? 0a 1f ?? 28 ?? ?? ?? 0a 07 08 93 61 d1 13 ?? 06 11 ?? 6f ?? ?? ?? 0a 26 08 04 6f ?? ?? ?? 0a 17 59 33 ?? 16 0c 2b ?? 08 17 59 18 58 0c 09 18 58 0d 09 03 6f ?? ?? ?? 0a 17 59 31 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}