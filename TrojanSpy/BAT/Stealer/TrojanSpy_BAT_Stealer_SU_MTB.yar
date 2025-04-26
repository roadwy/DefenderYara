
rule TrojanSpy_BAT_Stealer_SU_MTB{
	meta:
		description = "TrojanSpy:BAT/Stealer.SU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {02 7b 0a 00 00 04 11 09 11 0b 58 91 08 11 0b 91 2e 05 16 13 0a 2b 0d 11 0b 17 58 13 0b 11 0b 08 8e 69 32 dc } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}
rule TrojanSpy_BAT_Stealer_SU_MTB_2{
	meta:
		description = "TrojanSpy:BAT/Stealer.SU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_81_0 = {41 68 61 7a 75 6a 61 64 61 72 } //2 Ahazujadar
		$a_81_1 = {4f 71 6f 77 65 6d 65 63 61 6c 61 6c 69 62 61 62 75 68 75 68 61 } //2 Oqowemecalalibabuhuha
		$a_81_2 = {55 62 61 6b 61 63 75 70 69 6b 75 63 6f 72 6f 64 } //2 Ubakacupikucorod
	condition:
		((#a_81_0  & 1)*2+(#a_81_1  & 1)*2+(#a_81_2  & 1)*2) >=6
 
}