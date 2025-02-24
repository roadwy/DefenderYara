
rule TrojanSpy_BAT_Diztakun_SK_MTB{
	meta:
		description = "TrojanSpy:BAT/Diztakun.SK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {07 06 07 8e 69 6f 09 00 00 0a 8f 06 00 00 01 28 0a 00 00 0a 0c 09 08 28 0b 00 00 0a 0d 11 04 17 58 13 04 11 04 02 32 d8 } //2
		$a_81_1 = {38 38 38 5c 6f 62 6a 5c 52 65 6c 65 61 73 65 5c 38 38 38 2e 70 64 62 } //1 888\obj\Release\888.pdb
	condition:
		((#a_01_0  & 1)*2+(#a_81_1  & 1)*1) >=3
 
}