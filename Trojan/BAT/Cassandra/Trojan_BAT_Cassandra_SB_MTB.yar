
rule Trojan_BAT_Cassandra_SB_MTB{
	meta:
		description = "Trojan:BAT/Cassandra.SB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_81_0 = {42 75 69 6c 64 43 61 6c 63 20 50 72 6f 2e 64 6c 6c } //1 BuildCalc Pro.dll
		$a_81_1 = {53 74 72 75 63 74 75 72 61 6c 20 65 6e 67 69 6e 65 65 72 69 6e 67 20 63 61 6c 63 75 6c 61 74 69 6f 6e 20 73 6f 66 74 77 61 72 65 } //1 Structural engineering calculation software
		$a_81_2 = {53 74 72 75 63 74 75 72 65 54 65 63 68 20 53 6f 6c 75 74 69 6f 6e 73 } //1 StructureTech Solutions
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1) >=3
 
}