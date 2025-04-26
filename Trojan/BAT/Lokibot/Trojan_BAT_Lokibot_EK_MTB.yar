
rule Trojan_BAT_Lokibot_EK_MTB{
	meta:
		description = "Trojan:BAT/Lokibot.EK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_81_0 = {42 77 6e 76 71 72 6c 2e 64 6c 6c } //1 Bwnvqrl.dll
		$a_81_1 = {56 63 63 73 70 71 6d 6f 66 75 63 65 6c } //1 Vccspqmofucel
		$a_81_2 = {49 78 73 6e 62 6f 74 73 66 } //1 Ixsnbotsf
		$a_81_3 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_81_4 = {47 5a 69 70 53 74 72 65 61 6d } //1 GZipStream
		$a_81_5 = {52 65 70 6c 61 63 65 } //1 Replace
		$a_81_6 = {43 6f 6e 76 65 72 74 } //1 Convert
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1) >=7
 
}