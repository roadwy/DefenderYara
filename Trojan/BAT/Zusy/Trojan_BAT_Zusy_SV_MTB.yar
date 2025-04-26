
rule Trojan_BAT_Zusy_SV_MTB{
	meta:
		description = "Trojan:BAT/Zusy.SV!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {06 00 28 14 00 00 0a 72 a9 5c 00 70 28 15 00 00 0a 6f 16 00 00 0a 28 46 00 00 0a 0b 06 28 e5 00 00 0a 0c 20 e8 fb 01 00 8d 81 00 00 01 0d 73 d0 00 00 0a 09 6f e6 00 00 0a 08 8e } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}