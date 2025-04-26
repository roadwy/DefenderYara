
rule Trojan_BAT_Remcos_SML_MTB{
	meta:
		description = "Trojan:BAT/Remcos.SML!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_81_0 = {50 72 6f 6a 65 63 74 5f 43 61 6c 65 6e 64 61 72 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //1 Project_Calendar.Properties.Resources.resources
		$a_81_1 = {24 33 36 30 33 31 66 65 32 2d 35 33 36 65 2d 34 34 62 37 2d 61 65 34 64 2d 31 66 36 38 30 66 36 38 30 33 32 66 } //1 $36031fe2-536e-44b7-ae4d-1f680f68032f
		$a_81_2 = {47 35 5a 50 45 46 38 36 35 48 43 38 38 47 30 47 43 44 34 47 44 30 } //1 G5ZPEF865HC88G0GCD4GD0
		$a_81_3 = {42 69 74 6d 61 70 } //1 Bitmap
		$a_81_4 = {47 65 74 42 79 74 65 73 } //1 GetBytes
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=5
 
}