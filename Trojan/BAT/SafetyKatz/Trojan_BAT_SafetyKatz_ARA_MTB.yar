
rule Trojan_BAT_SafetyKatz_ARA_MTB{
	meta:
		description = "Trojan:BAT/SafetyKatz.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 04 00 00 "
		
	strings :
		$a_01_0 = {24 38 33 34 37 65 38 31 62 2d 38 39 66 63 2d 34 32 61 39 2d 62 32 32 63 2d 66 35 39 61 36 61 35 37 32 64 65 63 } //2 $8347e81b-89fc-42a9-b22c-f59a6a572dec
		$a_01_1 = {53 61 66 65 74 79 4b 61 74 7a 2e 70 64 62 } //2 SafetyKatz.pdb
		$a_01_2 = {57 61 69 74 46 6f 72 53 69 6e 67 6c 65 4f 62 6a 65 63 74 } //1 WaitForSingleObject
		$a_01_3 = {43 72 65 61 74 65 54 68 72 65 61 64 } //1 CreateThread
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=6
 
}