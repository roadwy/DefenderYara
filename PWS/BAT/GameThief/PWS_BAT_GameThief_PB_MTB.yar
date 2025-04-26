
rule PWS_BAT_GameThief_PB_MTB{
	meta:
		description = "PWS:BAT/GameThief.PB!MTB,SIGNATURE_TYPE_PEHSTR,0a 00 0a 00 06 00 00 "
		
	strings :
		$a_01_0 = {53 00 74 00 65 00 61 00 6c 00 65 00 72 00 } //5 Stealer
		$a_01_1 = {5c 00 47 00 72 00 6f 00 77 00 74 00 6f 00 70 00 69 00 61 00 5c 00 73 00 61 00 76 00 65 00 2e 00 64 00 61 00 74 00 } //2 \Growtopia\save.dat
		$a_01_2 = {74 00 78 00 74 00 46 00 69 00 6c 00 65 00 6e 00 61 00 6d 00 65 00 66 00 75 00 64 00 } //1 txtFilenamefud
		$a_01_3 = {47 65 74 50 61 73 73 77 6f 72 64 42 79 74 65 73 } //1 GetPasswordBytes
		$a_01_4 = {42 75 69 6c 64 53 74 65 61 6c 65 72 5f 43 6c 69 63 6b } //1 BuildStealer_Click
		$a_01_5 = {48 00 61 00 63 00 6b 00 } //1 Hack
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=10
 
}