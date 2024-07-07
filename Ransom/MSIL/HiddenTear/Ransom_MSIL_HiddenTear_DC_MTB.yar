
rule Ransom_MSIL_HiddenTear_DC_MTB{
	meta:
		description = "Ransom:MSIL/HiddenTear.DC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_81_0 = {76 73 73 61 64 6d 69 6e 2e 65 78 65 20 44 65 6c 65 74 65 20 53 68 61 64 6f 77 73 20 2f 41 6c 6c 20 2f 51 75 69 65 74 } //1 vssadmin.exe Delete Shadows /All /Quiet
		$a_81_1 = {44 69 73 61 62 6c 65 52 65 61 6c 74 69 6d 65 4d 6f 6e 69 74 6f 72 69 6e 67 } //1 DisableRealtimeMonitoring
		$a_81_2 = {44 69 73 61 62 6c 65 41 6e 74 69 53 70 79 77 61 72 65 } //1 DisableAntiSpyware
		$a_81_3 = {2e 65 6e 63 72 79 70 74 65 64 31 31 } //1 .encrypted11
		$a_81_4 = {40 74 75 74 61 6e 6f 74 61 2e 63 6f 6d } //1 @tutanota.com
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=5
 
}