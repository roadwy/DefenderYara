
rule Trojan_BAT_Jalapeno_NK_MTB{
	meta:
		description = "Trojan:BAT/Jalapeno.NK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_01_0 = {28 21 00 00 0a 13 09 11 09 28 03 00 00 06 11 09 14 fe 06 09 00 00 06 73 29 00 00 0a 28 08 00 00 06 } //3
		$a_01_1 = {41 66 68 6f 73 74 52 61 6e 64 6f 6d 46 6f 6c 64 65 72 } //1 AfhostRandomFolder
		$a_01_2 = {4d 69 63 72 6f 73 6f 66 74 45 64 67 65 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //1 MicrosoftEdge.Properties.Resources.resources
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=5
 
}