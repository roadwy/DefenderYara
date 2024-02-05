
rule Trojan_BAT_AgentTesla_MTX_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MTX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1a 00 1a 00 0e 00 00 02 00 "
		
	strings :
		$a_80_0 = {6f 63 72 76 62 2e 53 44 50 } //ocrvb.SDP  02 00 
		$a_80_1 = {41 73 79 6d 6d 65 74 72 69 63 } //Asymmetric  02 00 
		$a_80_2 = {6f 63 72 76 62 2e 52 65 73 6f 75 72 63 65 73 } //ocrvb.Resources  02 00 
		$a_80_3 = {42 65 73 74 46 69 74 4d 61 70 70 69 6e 67 41 74 74 72 69 62 75 74 65 2e 45 6e 75 6d 65 72 61 74 6f 72 53 69 6d 70 6c 65 } //BestFitMappingAttribute.EnumeratorSimple  02 00 
		$a_80_4 = {6f 63 72 76 62 } //ocrvb  02 00 
		$a_80_5 = {64 73 61 64 61 64 61 } //dsadada  02 00 
		$a_80_6 = {42 69 74 6d 61 70 } //Bitmap  02 00 
		$a_80_7 = {43 6f 6e 74 61 69 6e 73 4b 65 79 } //ContainsKey  02 00 
		$a_80_8 = {53 79 73 74 65 6d 2e 53 65 63 75 72 69 74 79 2e 43 72 79 70 74 6f 67 72 61 70 68 79 } //System.Security.Cryptography  02 00 
		$a_80_9 = {67 65 74 5f 41 73 73 65 6d 62 6c 79 } //get_Assembly  02 00 
		$a_80_10 = {73 65 74 5f 52 65 61 64 4f 6e 6c 79 } //set_ReadOnly  02 00 
		$a_80_11 = {43 72 65 61 74 65 44 69 72 65 63 74 6f 72 79 } //CreateDirectory  02 00 
		$a_80_12 = {44 65 6c 65 74 65 44 69 72 65 63 74 6f 72 79 } //DeleteDirectory  02 00 
		$a_80_13 = {43 72 65 61 74 65 5f 5f 49 6e 73 74 61 6e 63 65 5f 5f } //Create__Instance__  00 00 
	condition:
		any of ($a_*)
 
}