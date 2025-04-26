
rule TrojanDropper_BAT_Muddeling_A_dha{
	meta:
		description = "TrojanDropper:BAT/Muddeling.A!dha,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_01_0 = {33 35 64 37 37 32 66 62 2d 64 32 65 64 2d 34 39 62 62 2d 61 34 63 61 2d 61 62 35 35 66 34 66 66 61 34 39 37 } //2 35d772fb-d2ed-49bb-a4ca-ab55f4ffa497
		$a_01_1 = {5c 53 63 72 2e 6a 73 } //1 \Scr.js
		$a_01_2 = {5c 53 61 76 65 20 74 68 65 20 44 61 74 65 20 47 32 30 20 44 69 67 69 74 61 6c 20 45 63 6f 6e 6f 6d 79 } //1 \Save the Date G20 Digital Economy
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=2
 
}