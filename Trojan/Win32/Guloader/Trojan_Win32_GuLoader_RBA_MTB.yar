
rule Trojan_Win32_GuLoader_RBA_MTB{
	meta:
		description = "Trojan:Win32/GuLoader.RBA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_81_0 = {75 64 76 6c 67 65 6c 73 65 73 76 69 6e 64 75 65 74 73 } //1 udvlgelsesvinduets
		$a_81_1 = {68 6f 65 6a 61 64 65 6c 65 6e } //1 hoejadelen
		$a_81_2 = {73 65 6a 6c 62 61 61 64 73 } //1 sejlbaads
		$a_81_3 = {68 69 67 68 63 6f 75 72 74 2e 65 78 65 } //1 highcourt.exe
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}
rule Trojan_Win32_GuLoader_RBA_MTB_2{
	meta:
		description = "Trojan:Win32/GuLoader.RBA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_81_0 = {73 61 6e 64 66 61 6e 67 65 74 5c 6f 70 68 61 76 73 72 65 74 73 69 6e 64 65 68 61 76 65 72 73 5c 6d 61 72 6d 6f 72 66 6c 69 73 65 6e 73 } //1 sandfanget\ophavsretsindehavers\marmorflisens
		$a_81_1 = {5c 73 75 70 65 72 76 61 63 61 6e 65 6f 75 73 5c 66 6f 72 65 73 74 69 6c 6c 69 6e 67 73 76 65 72 64 6e 65 72 2e 63 6f 6c } //1 \supervacaneous\forestillingsverdner.col
		$a_81_2 = {35 5c 65 70 69 73 6f 64 65 72 6e 65 73 5c 4d 75 6c 74 69 73 63 72 65 65 6e 2e 66 72 61 } //1 5\episodernes\Multiscreen.fra
		$a_81_3 = {25 75 6e 6f 72 61 74 6f 72 69 61 6c 25 5c 75 6e 69 76 65 72 73 69 74 65 74 73 66 6f 72 6c 61 67 } //1 %unoratorial%\universitetsforlag
		$a_81_4 = {73 61 74 69 20 73 70 72 6f 67 6b 6c 66 74 20 73 61 72 6f 6e 69 64 65 } //1 sati sprogklft saronide
		$a_81_5 = {6b 6f 6f 6b 69 65 72 20 61 74 72 6f 70 69 6e 65 74 } //1 kookier atropinet
		$a_81_6 = {73 74 69 6e 6b 62 72 61 6e 64 65 6e } //1 stinkbranden
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1) >=7
 
}