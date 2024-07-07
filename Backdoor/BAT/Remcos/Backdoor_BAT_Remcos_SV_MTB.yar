
rule Backdoor_BAT_Remcos_SV_MTB{
	meta:
		description = "Backdoor:BAT/Remcos.SV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {24 38 31 30 61 39 65 35 38 2d 62 64 38 30 2d 34 62 65 61 2d 62 38 34 34 2d 33 31 65 34 65 32 39 32 31 66 63 33 } //2 $810a9e58-bd80-4bea-b844-31e4e2921fc3
		$a_01_1 = {4d 61 67 69 63 42 61 72 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 } //2 MagicBar.Properties.Resources
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}