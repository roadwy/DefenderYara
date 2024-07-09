
rule Trojan_BAT_Azorult_AZ_MTB{
	meta:
		description = "Trojan:BAT/Azorult.AZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {13 10 2b 0d 00 11 10 11 11 d2 6f ?? ?? ?? 0a 00 00 11 0f 6f ?? ?? ?? 0a 25 13 11 15 fe 01 16 fe 01 13 12 11 12 2d dd } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}