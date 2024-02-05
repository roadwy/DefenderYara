
rule Trojan_BAT_AgentTesla_MTS_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MTS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1c 00 1c 00 0f 00 00 02 00 "
		
	strings :
		$a_80_0 = {42 65 73 74 46 69 74 4d 61 70 70 69 6e 67 41 74 74 72 69 62 75 74 65 2e 45 6e 75 6d 65 72 61 74 6f 72 53 69 6d 70 6c 65 } //BestFitMappingAttribute.EnumeratorSimple  02 00 
		$a_80_1 = {54 69 65 6e 64 61 2e 52 65 73 6f 75 72 63 65 73 } //Tienda.Resources  02 00 
		$a_80_2 = {4d 75 69 52 65 73 6f 75 72 63 65 4d 61 70 45 6e 74 72 79 46 69 65 6c 64 49 64 } //MuiResourceMapEntryFieldId  02 00 
		$a_80_3 = {54 69 65 6e 64 61 2e 55 74 69 6c } //Tienda.Util  02 00 
		$a_80_4 = {4e 65 77 4c 61 74 65 42 69 6e 64 69 6e 67 } //NewLateBinding  02 00 
		$a_80_5 = {4c 61 74 65 49 6e 64 65 78 47 65 74 } //LateIndexGet  02 00 
		$a_80_6 = {54 69 65 6e 64 61 2e 55 74 69 6c 2e 72 65 73 6f 75 72 63 65 73 } //Tienda.Util.resources  02 00 
		$a_80_7 = {42 69 64 69 43 61 74 65 67 6f 72 79 } //BidiCategory  02 00 
		$a_80_8 = {46 65 65 64 62 61 63 6b 53 69 7a 65 } //FeedbackSize  02 00 
		$a_80_9 = {4d 69 6e 6f 72 56 65 72 73 69 6f 6e } //MinorVersion  02 00 
		$a_80_10 = {41 70 70 6c 69 63 61 74 69 6f 6e 49 64 65 6e 74 69 74 79 } //ApplicationIdentity  02 00 
		$a_80_11 = {43 72 65 61 74 65 5f 5f 49 6e 73 74 61 6e 63 65 5f 5f } //Create__Instance__  02 00 
		$a_80_12 = {41 73 79 6d 6d 65 74 72 69 63 } //Asymmetric  02 00 
		$a_80_13 = {44 65 62 75 67 67 65 72 4e 6f 6e 55 73 65 72 43 6f 64 65 41 74 74 72 69 62 75 74 65 } //DebuggerNonUserCodeAttribute  02 00 
		$a_80_14 = {42 69 74 6d 61 70 } //Bitmap  00 00 
	condition:
		any of ($a_*)
 
}