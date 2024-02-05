
rule Trojan_BAT_AgentTesla_MTI_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MTI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 0f 00 00 02 00 "
		
	strings :
		$a_80_0 = {53 71 6c 43 6f 6d 6d 61 6e 64 } //SqlCommand  02 00 
		$a_80_1 = {70 61 73 73 77 6f 72 64 } //password  02 00 
		$a_80_2 = {49 6e 66 6f 43 61 63 68 65 } //InfoCache  02 00 
		$a_80_3 = {49 6e 76 6f 6b 65 } //Invoke  02 00 
		$a_80_4 = {47 65 74 54 79 70 65 } //GetType  02 00 
		$a_80_5 = {47 65 74 50 69 78 65 6c } //GetPixel  02 00 
		$a_80_6 = {65 6d 61 69 6c } //email  02 00 
		$a_80_7 = {53 51 4c 4d 61 6e 61 67 65 72 } //SQLManager  02 00 
		$a_80_8 = {53 71 6c 44 61 74 61 52 65 61 64 65 72 } //SqlDataReader  02 00 
		$a_80_9 = {44 65 6c 65 74 65 52 6f 77 } //DeleteRow  02 00 
		$a_80_10 = {42 69 64 69 43 61 74 65 67 6f 72 79 } //BidiCategory  02 00 
		$a_80_11 = {4d 69 6e 6f 72 56 65 72 73 69 6f 6e } //MinorVersion  02 00 
		$a_80_12 = {41 73 79 6d 6d 65 74 72 69 63 } //Asymmetric  02 00 
		$a_80_13 = {42 65 73 74 46 69 74 4d 61 70 70 69 6e 67 41 74 74 72 69 62 75 74 65 2e 45 6e 75 6d 65 72 61 74 6f 72 53 69 6d 70 6c 65 } //BestFitMappingAttribute.EnumeratorSimple  02 00 
		$a_80_14 = {52 50 46 3a 53 6d 61 72 74 41 73 73 65 6d 62 6c 79 } //RPF:SmartAssembly  00 00 
	condition:
		any of ($a_*)
 
}