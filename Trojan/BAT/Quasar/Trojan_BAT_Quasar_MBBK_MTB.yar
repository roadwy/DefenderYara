
rule Trojan_BAT_Quasar_MBBK_MTB{
	meta:
		description = "Trojan:BAT/Quasar.MBBK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {73 0d 00 00 0a 0a 06 28 ?? 00 00 0a 03 50 6f 0f 00 00 0a 6f 10 00 00 0a 0b 73 11 00 00 0a 0c 08 07 6f 12 00 00 0a 08 18 6f 13 00 00 0a 08 6f 14 00 00 0a 02 50 16 02 50 8e 69 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}