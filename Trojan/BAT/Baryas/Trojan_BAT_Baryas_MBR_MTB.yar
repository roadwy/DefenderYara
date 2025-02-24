
rule Trojan_BAT_Baryas_MBR_MTB{
	meta:
		description = "Trojan:BAT/Baryas.MBR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {59 11 36 20 d1 01 00 00 95 5f 11 36 20 9b 0f 00 00 95 61 58 81 0b 00 00 01 11 28 16 9a 18 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}