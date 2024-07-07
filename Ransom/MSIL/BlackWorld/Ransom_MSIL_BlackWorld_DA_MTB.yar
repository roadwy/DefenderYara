
rule Ransom_MSIL_BlackWorld_DA_MTB{
	meta:
		description = "Ransom:MSIL/BlackWorld.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_81_0 = {42 6c 61 63 6b 20 57 6f 72 6c 64 20 52 61 6e 73 6f 6d 77 61 72 65 2e 65 78 65 } //1 Black World Ransomware.exe
		$a_81_1 = {42 6c 61 63 6b 5f 57 6f 72 6c 64 5f 52 61 6e 73 6f 6d 77 61 72 65 2e 50 72 6f 70 65 72 74 69 65 73 } //1 Black_World_Ransomware.Properties
		$a_81_2 = {42 6c 61 63 6b 20 57 6f 72 6c 64 20 52 61 6e 73 6f 6d 77 61 72 65 2e 70 64 62 } //1 Black World Ransomware.pdb
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1) >=3
 
}