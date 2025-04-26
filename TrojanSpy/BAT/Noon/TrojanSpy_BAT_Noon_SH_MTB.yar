
rule TrojanSpy_BAT_Noon_SH_MTB{
	meta:
		description = "TrojanSpy:BAT/Noon.SH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {11 07 61 13 1a 07 09 17 58 08 5d 91 13 1b 11 1a 11 1b 59 } //2
		$a_81_1 = {68 65 69 64 69 5f 73 63 68 77 61 72 74 7a 5f 43 39 36 38 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 } //2 heidi_schwartz_C968.Properties.Resources
	condition:
		((#a_01_0  & 1)*2+(#a_81_1  & 1)*2) >=4
 
}