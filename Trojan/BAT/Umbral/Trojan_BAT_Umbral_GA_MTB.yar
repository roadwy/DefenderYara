
rule Trojan_BAT_Umbral_GA_MTB{
	meta:
		description = "Trojan:BAT/Umbral.GA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,11 00 0f 00 07 00 00 "
		
	strings :
		$a_80_0 = {55 4d 42 52 41 4c 20 53 54 45 41 4c 45 52 } //UMBRAL STEALER  10
		$a_80_1 = {3a 2f 2f 64 69 73 63 6f 72 64 2e 63 6f 6d 2f 61 70 69 2f 77 65 62 68 6f 6f 6b 73 2f } //://discord.com/api/webhooks/  1
		$a_80_2 = {3a 2f 2f 67 69 74 68 75 62 2e 63 6f 6d 2f 42 6c 61 6e 6b 2d 63 2f 55 6d 62 72 61 6c 2d 53 74 65 61 6c 65 72 } //://github.com/Blank-c/Umbral-Stealer  5
		$a_80_3 = {57 65 62 68 6f 6f 6b } //Webhook  1
		$a_80_4 = {53 63 72 65 65 6e 73 68 6f 74 } //Screenshot  1
		$a_80_5 = {53 74 65 61 6c } //Steal  1
		$a_80_6 = {62 75 69 6c 64 65 72 } //builder  1
	condition:
		((#a_80_0  & 1)*10+(#a_80_1  & 1)*1+(#a_80_2  & 1)*5+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1+(#a_80_6  & 1)*1) >=15
 
}