
rule Trojan_BAT_AgentTesla_AAV_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.AAV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {54 00 61 00 6e 00 6b 00 73 00 47 00 61 00 6d 00 65 00 5f 00 56 00 34 00 } //1 TanksGame_V4
		$a_01_1 = {53 00 63 00 72 00 61 00 70 00 65 00 72 00 2e 00 57 00 68 00 69 00 74 00 65 00 } //1 Scraper.White
		$a_01_2 = {59 00 74 00 67 00 68 00 2e 00 65 00 78 00 65 00 } //1 Ytgh.exe
		$a_01_3 = {53 65 74 50 69 78 65 6c } //1 SetPixel
		$a_01_4 = {54 6f 53 42 79 74 65 } //1 ToSByte
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}