
rule TrojanSpy_BAT_Starter_ARA_MTB{
	meta:
		description = "TrojanSpy:BAT/Starter.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_01_0 = {3a 00 2f 00 2f 00 72 00 32 00 2e 00 6f 00 68 00 79 00 6f 00 75 00 6c 00 6f 00 6f 00 6b 00 73 00 74 00 75 00 70 00 69 00 64 00 2e 00 77 00 69 00 6e 00 2f 00 } //2 ://r2.ohyoulookstupid.win/
		$a_01_1 = {2d 00 57 00 65 00 62 00 53 00 65 00 73 00 73 00 69 00 6f 00 6e 00 20 00 24 00 53 00 20 00 2d 00 55 00 73 00 65 00 42 00 61 00 73 00 69 00 63 00 50 00 61 00 72 00 73 00 69 00 6e 00 67 00 29 00 2e 00 43 00 6f 00 6e 00 74 00 65 00 6e 00 74 00 } //2 -WebSession $S -UseBasicParsing).Content
		$a_01_2 = {49 00 6e 00 76 00 6f 00 6b 00 65 00 2d 00 45 00 78 00 70 00 72 00 65 00 73 00 73 00 69 00 6f 00 6e 00 20 00 28 00 49 00 6e 00 76 00 6f 00 6b 00 65 00 2d 00 57 00 65 00 62 00 52 00 65 00 71 00 75 00 65 00 73 00 74 00 } //2 Invoke-Expression (Invoke-WebRequest
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2) >=6
 
}