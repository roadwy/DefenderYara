
rule TrojanSpy_BAT_Kostioul_A{
	meta:
		description = "TrojanSpy:BAT/Kostioul.A,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {41 00 4d 00 [0-0a] 43 00 4f 00 4e 00 46 00 49 00 47 [0-0a] 55 00 4e 00 50 00 45 00 [0-10] 55 00 52 00 41 00 4c 00 59 00 41 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}