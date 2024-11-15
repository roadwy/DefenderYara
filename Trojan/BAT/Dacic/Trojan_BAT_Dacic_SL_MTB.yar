
rule Trojan_BAT_Dacic_SL_MTB{
	meta:
		description = "Trojan:BAT/Dacic.SL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_81_0 = {24 34 31 62 37 35 62 66 65 2d 65 61 36 38 2d 34 32 31 65 2d 38 32 66 33 2d 63 35 30 63 38 66 34 37 65 38 30 61 } //2 $41b75bfe-ea68-421e-82f3-c50c8f47e80a
		$a_81_1 = {43 6f 6d 70 61 6e 79 4e 65 74 77 6f 72 6b 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 } //2 CompanyNetwork.Properties.Resources
		$a_81_2 = {53 68 6f 77 63 61 72 64 20 47 6f 74 68 69 63 } //1 Showcard Gothic
	condition:
		((#a_81_0  & 1)*2+(#a_81_1  & 1)*2+(#a_81_2  & 1)*1) >=5
 
}