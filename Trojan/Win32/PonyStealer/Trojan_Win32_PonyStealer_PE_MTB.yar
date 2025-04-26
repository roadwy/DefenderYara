
rule Trojan_Win32_PonyStealer_PE_MTB{
	meta:
		description = "Trojan:Win32/PonyStealer.PE!MTB,SIGNATURE_TYPE_PEHSTR,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {54 68 65 61 74 72 65 73 } //1 Theatres
		$a_01_1 = {52 41 46 54 45 52 45 44 } //1 RAFTERED
		$a_01_2 = {6d 65 6c 6c 65 6d 61 6d 65 72 69 6b 61 6e 73 6b } //1 mellemamerikansk
		$a_01_3 = {49 00 42 00 72 00 46 00 36 00 39 00 58 00 4f 00 53 00 77 00 5a 00 41 00 61 00 56 00 61 00 39 00 73 00 76 00 6e 00 38 00 32 00 } //1 IBrF69XOSwZAaVa9svn82
		$a_01_4 = {48 00 5a 00 4b 00 31 00 67 00 63 00 76 00 46 00 46 00 62 00 65 00 4c 00 54 00 6a 00 51 00 68 00 77 00 32 00 5a 00 36 00 78 00 50 00 6c 00 5a 00 61 00 69 00 64 00 55 00 38 00 77 00 6b 00 73 00 38 00 39 00 } //1 HZK1gcvFFbeLTjQhw2Z6xPlZaidU8wks89
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}