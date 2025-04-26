
rule Trojan_Win32_Emotet_DS{
	meta:
		description = "Trojan:Win32/Emotet.DS,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_01_0 = {55 71 78 49 6b 42 65 4e 59 68 4b 52 2e 70 64 62 } //1 UqxIkBeNYhKR.pdb
		$a_01_1 = {32 67 65 72 47 57 40 34 68 65 72 68 77 2a 39 32 38 33 79 34 68 75 57 4f 2e 70 64 62 } //1 2gerGW@4herhw*9283y4huWO.pdb
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=1
 
}