
rule Trojan_BAT_Remcos_MYH_MTB{
	meta:
		description = "Trojan:BAT/Remcos.MYH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_03_0 = {7e 1e 00 00 04 72 e9 04 00 70 72 ed 04 00 70 6f ?? ?? ?? 0a 28 ?? ?? ?? 06 28 ?? ?? ?? 0a 28 ?? ?? ?? 06 28 ?? ?? ?? 0a 0b 28 ?? ?? ?? 06 14 72 f3 04 00 70 17 8d 17 00 00 01 25 16 07 } //2
		$a_01_1 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_01_2 = {52 65 70 6c 61 63 65 } //1 Replace
		$a_01_3 = {53 00 53 00 4c 00 32 00 5f 00 41 00 69 00 6d 00 5f 00 41 00 73 00 73 00 69 00 73 00 74 00 } //1 SSL2_Aim_Assist
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=5
 
}