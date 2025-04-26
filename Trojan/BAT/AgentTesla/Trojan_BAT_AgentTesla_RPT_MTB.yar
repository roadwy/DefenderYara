
rule Trojan_BAT_AgentTesla_RPT_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.RPT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {38 00 64 00 75 00 61 00 6e 00 6a 00 69 00 6e 00 2e 00 6e 00 65 00 74 00 } //1 8duanjin.net
		$a_01_1 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 } //1 powershell
		$a_01_2 = {44 00 78 00 6f 00 77 00 6e 00 78 00 6c 00 6f 00 78 00 61 00 64 00 44 00 78 00 61 00 74 00 78 00 78 00 61 00 78 00 } //1 DxownxloxadDxatxxax
		$a_01_3 = {52 65 70 6c 61 63 65 } //1 Replace
		$a_01_4 = {57 65 62 43 6c 69 65 6e 74 } //1 WebClient
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}
rule Trojan_BAT_AgentTesla_RPT_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.RPT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 0a 00 00 "
		
	strings :
		$a_01_0 = {33 00 2e 00 37 00 31 00 2e 00 33 00 39 00 2e 00 32 00 32 00 34 00 } //1 3.71.39.224
		$a_01_1 = {70 00 65 00 61 00 63 00 65 00 } //1 peace
		$a_01_2 = {6c 00 6f 00 61 00 64 00 65 00 72 00 } //1 loader
		$a_01_3 = {75 00 70 00 6c 00 6f 00 61 00 64 00 73 00 } //1 uploads
		$a_01_4 = {48 00 72 00 73 00 72 00 69 00 75 00 61 00 6a 00 2e 00 70 00 6e 00 67 00 } //1 Hrsriuaj.png
		$a_01_5 = {51 00 65 00 64 00 66 00 74 00 6c 00 79 00 69 00 63 00 76 00 66 00 6e 00 } //1 Qedftlyicvfn
		$a_01_6 = {67 65 74 5f 41 73 73 65 6d 62 6c 79 } //1 get_Assembly
		$a_01_7 = {52 65 61 64 42 79 74 65 73 } //1 ReadBytes
		$a_01_8 = {57 65 62 52 65 73 70 6f 6e 73 65 } //1 WebResponse
		$a_01_9 = {52 65 76 65 72 73 65 } //1 Reverse
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1) >=10
 
}
rule Trojan_BAT_AgentTesla_RPT_MTB_3{
	meta:
		description = "Trojan:BAT/AgentTesla.RPT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {63 00 64 00 6e 00 2e 00 64 00 69 00 73 00 63 00 6f 00 72 00 64 00 61 00 70 00 70 00 2e 00 63 00 6f 00 6d 00 } //1 cdn.discordapp.com
		$a_01_1 = {56 00 77 00 71 00 78 00 66 00 2e 00 6a 00 70 00 67 00 } //1 Vwqxf.jpg
		$a_01_2 = {43 00 73 00 67 00 75 00 79 00 74 00 6f 00 74 00 6c 00 74 00 6b 00 6d 00 61 00 79 00 67 00 66 00 61 00 70 00 70 00 67 00 2e 00 49 00 69 00 79 00 71 00 78 00 74 00 6e 00 70 00 6b 00 63 00 75 00 62 00 } //1 Csguytotltkmaygfappg.Iiyqxtnpkcub
		$a_01_3 = {52 00 6f 00 61 00 79 00 79 00 6e 00 72 00 6e 00 73 00 } //1 Roayynrns
		$a_01_4 = {45 00 6d 00 61 00 69 00 6c 00 20 00 43 00 68 00 65 00 63 00 6b 00 65 00 72 00 20 00 50 00 72 00 6f 00 } //1 Email Checker Pro
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}