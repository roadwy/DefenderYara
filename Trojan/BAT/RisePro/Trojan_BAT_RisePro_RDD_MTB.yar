
rule Trojan_BAT_RisePro_RDD_MTB{
	meta:
		description = "Trojan:BAT/RisePro.RDD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_01_0 = {63 39 62 38 65 34 36 64 2d 32 38 64 61 2d 34 33 37 64 2d 61 37 38 39 2d 32 30 35 62 65 39 35 34 61 65 32 30 } //2 c9b8e46d-28da-437d-a789-205be954ae20
		$a_01_1 = {42 6f 74 73 6f 66 74 } //1 Botsoft
		$a_01_2 = {4b 4c 43 50 20 55 70 64 61 74 65 20 31 38 2e 35 2e 30 20 53 65 74 75 70 } //1 KLCP Update 18.5.0 Setup
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=4
 
}