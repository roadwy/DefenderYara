
rule TrojanDropper_Win64_RollSling_A_dha{
	meta:
		description = "TrojanDropper:Win64/RollSling.A!dha,SIGNATURE_TYPE_PEHSTR_EXT,ffffffc8 00 ffffffc8 00 02 00 00 "
		
	strings :
		$a_01_0 = {2d 44 46 30 39 2d 41 41 38 36 2d 59 49 37 38 2d } //100 -DF09-AA86-YI78-
		$a_01_1 = {2d 30 39 43 37 2d 38 38 36 45 2d 49 49 37 46 2d } //100 -09C7-886E-II7F-
	condition:
		((#a_01_0  & 1)*100+(#a_01_1  & 1)*100) >=200
 
}