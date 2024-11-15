
rule Trojan_BAT_AgentTesla_SMX_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.SMX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {00 03 12 02 28 47 00 00 0a 6f 48 00 00 0a 00 03 12 02 28 49 00 00 0a 6f 48 00 00 0a 00 03 12 02 28 4a 00 00 0a 6f 48 00 00 0a 00 2b 15 03 6f 4b 00 00 0a 19 58 04 31 03 16 2b 01 17 13 04 11 04 2d be } //1
		$a_81_1 = {47 65 74 50 69 78 65 6c } //1 GetPixel
		$a_81_2 = {42 69 74 6d 61 70 } //1 Bitmap
		$a_81_3 = {43 6f 6e 6e 65 63 74 46 6f 75 72 2e 4b 61 73 73 61 2e 4e 69 65 75 77 65 4b 6c 61 6e 74 2e 72 65 73 6f 75 72 63 65 73 } //1 ConnectFour.Kassa.NieuweKlant.resources
	condition:
		((#a_00_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}