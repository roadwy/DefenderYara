
rule Ransom_Win64_Basta_SAA_MTB{
	meta:
		description = "Ransom:Win64/Basta.SAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {88 01 0f be 44 24 ?? 0f be 4c 24 ?? d3 e0 88 44 24 ?? 0f be 44 24 ?? 0f be 4c 24 ?? 0b c1 88 44 24 ?? 48 ?? ?? ?? ?? ?? ?? ?? 48 b9 ?? ?? ?? ?? ?? ?? ?? ?? 48 ?? ?? 48 ?? ?? 48 } //1
		$a_00_1 = {44 00 69 00 73 00 69 00 6e 00 63 00 6c 00 69 00 6e 00 61 00 74 00 69 00 6f 00 20 00 69 00 6d 00 70 00 69 00 6e 00 67 00 65 00 6d 00 65 00 6e 00 } //1 Disinclinatio impingemen
	condition:
		((#a_03_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}