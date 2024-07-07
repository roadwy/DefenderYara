
rule Trojan_BAT_Spynoon_AATQ_MTB{
	meta:
		description = "Trojan:BAT/Spynoon.AATQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {44 65 61 6e 2e 45 64 77 61 72 64 73 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 } //2 Dean.Edwards.Properties.Resources
		$a_01_1 = {66 65 33 64 34 35 62 66 2d 66 32 64 61 2d 34 62 37 38 2d 39 61 65 36 2d 63 33 39 33 37 35 33 38 33 38 32 35 } //2 fe3d45bf-f2da-4b78-9ae6-c39375383825
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}