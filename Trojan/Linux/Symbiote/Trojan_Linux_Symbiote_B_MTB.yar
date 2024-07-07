
rule Trojan_Linux_Symbiote_B_MTB{
	meta:
		description = "Trojan:Linux/Symbiote.B!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_00_0 = {8b 45 d8 48 98 0f b6 84 05 a0 fb ff ff 84 c0 75 0d 8b 45 d8 48 98 c6 84 05 a0 fb ff ff 20 8b 45 d4 48 98 48 03 45 c0 8b 55 d8 48 63 d2 0f b6 94 15 a0 fb ff ff 88 10 83 45 d4 01 83 45 d8 01 48 8b 45 e0 3b 45 d8 7f b8 } //1
		$a_00_1 = {8b 45 e8 0f b6 84 05 c0 fb ff ff 84 c0 75 0c 48 8b 45 e8 c6 84 05 c0 fb ff ff 20 8b 45 d0 48 98 48 03 45 c0 48 8b 55 e8 0f b6 94 15 c0 fb ff ff 88 10 83 45 d0 01 48 83 45 e8 01 48 8b 45 e8 48 3b 45 d8 7c ba } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1) >=1
 
}