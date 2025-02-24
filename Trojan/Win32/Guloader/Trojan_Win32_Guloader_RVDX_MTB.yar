
rule Trojan_Win32_Guloader_RVDX_MTB{
	meta:
		description = "Trojan:Win32/Guloader.RVDX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_81_0 = {5c 64 65 61 6d 62 75 6c 61 74 6f 72 69 65 73 5c 69 72 72 61 74 69 6f 6e 61 6c 5c 61 6d 61 72 69 6c 6c 6f } //1 \deambulatories\irrational\amarillo
		$a_81_1 = {50 65 72 66 75 73 65 73 5c 66 72 61 66 6c 79 74 6e 69 6e 67 65 6e } //1 Perfuses\fraflytningen
		$a_81_2 = {25 6b 6f 67 65 72 73 6b 65 72 6e 65 25 5c 70 72 65 61 63 75 74 65 5c 70 61 74 65 6e 74 65 72 69 6e 67 73 } //1 %kogerskerne%\preacute\patenterings
		$a_81_3 = {61 6a 61 74 73 61 20 64 72 6f 77 6e 73 20 69 6d 6d 75 6e 6f 67 65 6e 69 63 69 74 79 } //1 ajatsa drowns immunogenicity
		$a_81_4 = {66 6f 75 6c 20 68 6f 6d 62 75 72 67 } //1 foul homburg
		$a_81_5 = {6e 67 6f 20 66 6f 72 6c 65 6e 65 72 2e 65 78 65 } //1 ngo forlener.exe
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1) >=6
 
}