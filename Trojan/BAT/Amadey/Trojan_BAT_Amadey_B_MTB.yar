
rule Trojan_BAT_Amadey_B_MTB{
	meta:
		description = "Trojan:BAT/Amadey.B!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_01_0 = {57 b5 a2 3d 09 0f 00 00 00 fa 25 33 00 16 00 00 01 00 00 00 33 00 00 00 42 00 00 00 50 00 00 00 7e } //4
		$a_01_1 = {47 65 74 50 72 6f 63 65 73 73 42 79 49 64 } //1 GetProcessById
	condition:
		((#a_01_0  & 1)*4+(#a_01_1  & 1)*1) >=5
 
}