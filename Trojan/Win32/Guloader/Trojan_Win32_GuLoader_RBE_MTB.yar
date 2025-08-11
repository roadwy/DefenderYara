
rule Trojan_Win32_GuLoader_RBE_MTB{
	meta:
		description = "Trojan:Win32/GuLoader.RBE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_81_0 = {61 69 6c 73 20 67 6e 61 74 68 69 63 20 61 66 73 6b 72 6b 6b 65 6c 73 65 73 76 61 61 62 6e 65 74 } //1 ails gnathic afskrkkelsesvaabnet
		$a_81_1 = {6d 65 73 6f 73 69 67 6d 6f 69 64 20 75 64 66 79 6c 64 6e 69 6e 67 72 73 } //1 mesosigmoid udfyldningrs
		$a_81_2 = {79 6f 72 20 73 65 62 75 6d 20 64 69 73 63 72 65 65 74 } //1 yor sebum discreet
		$a_81_3 = {75 73 69 6b 6b 65 72 68 65 64 73 6d 6f 6d 65 6e 74 65 74 73 20 64 65 6b 6f 64 6e 69 6e 67 65 72 73 2e 65 78 65 } //1 usikkerhedsmomentets dekodningers.exe
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=3
 
}
rule Trojan_Win32_GuLoader_RBE_MTB_2{
	meta:
		description = "Trojan:Win32/GuLoader.RBE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_81_0 = {5c 53 79 62 61 72 69 74 69 73 6d 5c 55 6e 64 65 72 70 72 69 6b 6b 65 64 65 } //1 \Sybaritism\Underprikkede
		$a_81_1 = {53 6b 65 6d 61 6c 69 73 74 65 72 6e 65 2e 69 6e 69 } //1 Skemalisterne.ini
		$a_81_2 = {5c 6b 6f 6e 74 6f 72 74 65 6c 65 66 6f 6e 5c 6f 63 74 61 76 61 6c 2e 6a 70 67 } //1 \kontortelefon\octaval.jpg
		$a_81_3 = {61 66 6c 6f 65 73 6e 69 6e 67 73 6f 70 67 61 76 65 6e 20 71 75 61 6e 74 69 74 69 76 65 6e 65 73 73 } //1 afloesningsopgaven quantitiveness
		$a_81_4 = {62 6f 6c 6c 65 72 } //1 boller
		$a_81_5 = {6e 65 64 73 61 62 6c 69 6e 67 65 6e } //1 nedsablingen
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1) >=6
 
}