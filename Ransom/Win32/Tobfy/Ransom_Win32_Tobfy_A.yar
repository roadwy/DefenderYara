
rule Ransom_Win32_Tobfy_A{
	meta:
		description = "Ransom:Win32/Tobfy.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {6a 01 ff d6 68 ?? ?? ?? ?? e8 ?? ?? ?? ?? 83 c4 04 6a 01 ff d6 a1 ?? ?? ?? ?? 6a 00 6a 00 68 04 02 00 00 50 ff d7 eb a5 } //1
		$a_03_1 = {ff d7 6a 00 6a 02 8b f8 ff d3 8b f0 83 fe ff 74 ?? 8d 44 24 ?? 50 56 c7 44 24 ?? 28 01 00 00 ff d5 85 c0 74 ?? 8b 5c 24 ?? 8d 4c 24 ?? 51 56 ff d3 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}