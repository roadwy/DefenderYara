
rule Trojan_BAT_Barys_VD_MTB{
	meta:
		description = "Trojan:BAT/Barys.VD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 03 00 00 "
		
	strings :
		$a_01_0 = {73 65 72 76 65 72 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //5 server.Resources.resources
		$a_01_1 = {53 6b 69 44 7a 45 58 20 3a 20 68 74 74 70 73 3a 2f 2f 64 69 73 63 6f 72 64 2e 67 67 2f 74 48 78 76 59 76 57 5a 56 38 } //5 SkiDzEX : https://discord.gg/tHxvYvWZV8
		$a_01_2 = {63 63 38 66 61 64 30 33 2d 38 31 36 65 2d 34 33 32 63 2d 39 62 39 32 2d 30 30 31 66 32 64 38 31 39 34 37 31 } //5 cc8fad03-816e-432c-9b92-001f2d819471
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5+(#a_01_2  & 1)*5) >=15
 
}