
rule Trojan_BAT_APosT_SK_MTB{
	meta:
		description = "Trojan:BAT/APosT.SK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {11 07 11 08 6f 5f 00 00 0a 26 11 04 17 58 13 04 11 08 17 58 13 08 11 08 11 07 6f 50 00 00 0a 32 df } //2
		$a_01_1 = {52 50 45 33 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //2 RPE3.Properties.Resources.resources
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}