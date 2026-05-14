
rule TrojanSpy_BAT_Noon_AMTB{
	meta:
		description = "TrojanSpy:BAT/Noon!AMTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_80_0 = {68 74 74 70 3a 2f 2f 31 38 35 2e 32 34 36 2e 32 32 30 2e 31 32 31 2f 76 69 6b } //http://185.246.220.121/vik  1
		$a_80_1 = {48 41 57 4b 2e 48 41 57 4b } //HAWK.HAWK  1
		$a_80_2 = {52 75 6e 68 61 77 6b } //Runhawk  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1) >=3
 
}