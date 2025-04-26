
rule Trojan_BAT_Remcos_ABDI_MTB{
	meta:
		description = "Trojan:BAT/Remcos.ABDI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_03_0 = {02 07 02 8e 69 5d 91 06 07 06 8e 69 5d 91 61 28 ?? ?? ?? 0a 02 07 17 58 02 8e 69 5d 91 28 ?? ?? ?? 0a 59 20 ?? ?? ?? 00 58 20 ?? ?? ?? 00 5d d2 9c } //4
		$a_01_1 = {45 00 63 00 6f 00 42 00 6f 00 6f 00 73 00 74 00 } //1 EcoBoost
		$a_01_2 = {37 00 34 00 35 00 34 00 34 00 35 00 42 00 4a 00 35 00 43 00 48 00 4f 00 38 00 39 00 38 00 30 00 46 00 47 00 47 00 41 00 5a 00 37 00 } //1 745445BJ5CHO8980FGGAZ7
	condition:
		((#a_03_0  & 1)*4+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=6
 
}