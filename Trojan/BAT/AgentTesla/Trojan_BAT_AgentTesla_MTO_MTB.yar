
rule Trojan_BAT_AgentTesla_MTO_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MTO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 08 00 00 02 00 "
		
	strings :
		$a_80_0 = {42 4d 53 31 2e 52 65 73 6f 75 72 63 65 73 } //BMS1.Resources  02 00 
		$a_80_1 = {54 79 70 65 49 6e 66 6f } //TypeInfo  02 00 
		$a_80_2 = {42 4d 53 31 2e 53 68 65 65 74 31 } //BMS1.Sheet1  02 00 
		$a_80_3 = {41 73 79 6d 6d 65 74 72 69 63 } //Asymmetric  02 00 
		$a_80_4 = {68 74 74 70 3a 2f 2f 77 77 77 2e 74 65 6d 70 75 72 69 2e 6f 72 67 2f 44 61 74 61 53 65 74 31 2e 78 73 64 } //http://www.tempuri.org/DataSet1.xsd  02 00 
		$a_80_5 = {42 65 73 74 46 69 74 4d 61 70 70 69 6e 67 41 74 74 72 69 62 75 74 65 2e 45 6e 75 6d 65 72 61 74 6f 72 53 69 6d 70 6c 65 } //BestFitMappingAttribute.EnumeratorSimple  02 00 
		$a_80_6 = {47 65 74 50 69 78 65 6c } //GetPixel  02 00 
		$a_80_7 = {42 69 64 69 43 61 74 65 67 6f 72 79 } //BidiCategory  00 00 
	condition:
		any of ($a_*)
 
}