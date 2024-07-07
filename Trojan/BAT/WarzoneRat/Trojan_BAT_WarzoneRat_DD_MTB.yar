
rule Trojan_BAT_WarzoneRat_DD_MTB{
	meta:
		description = "Trojan:BAT/WarzoneRat.DD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_81_0 = {24 30 36 35 34 33 32 63 39 2d 37 37 66 31 2d 34 33 37 36 2d 62 30 66 63 2d 62 31 63 61 65 63 32 34 65 32 62 61 } //1 $065432c9-77f1-4376-b0fc-b1caec24e2ba
		$a_81_1 = {4d 6f 64 65 6c 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 } //1 Model.Properties.Resources
		$a_81_2 = {4d 6f 64 65 6c 2e 46 6f 72 6d 31 2e 72 65 73 6f 75 72 63 65 73 } //1 Model.Form1.resources
		$a_81_3 = {4b 75 72 64 69 73 68 43 6f 64 65 72 50 72 6f 64 75 63 74 73 } //1 KurdishCoderProducts
		$a_81_4 = {43 68 65 63 6b 46 72 65 71 75 65 6e 63 69 65 73 } //1 CheckFrequencies
		$a_81_5 = {67 65 74 5f 72 61 69 6e 62 6f 77 73 69 78 } //1 get_rainbowsix
		$a_81_6 = {67 65 74 5f 73 61 6b 6f } //1 get_sako
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1) >=7
 
}