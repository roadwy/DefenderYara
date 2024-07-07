
rule Trojan_Win64_Barys_EC_MTB{
	meta:
		description = "Trojan:Win64/Barys.EC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 05 00 00 "
		
	strings :
		$a_01_0 = {6e 6f 2d 73 74 65 6d 2d } //2 no-stem-
		$a_01_1 = {69 6d 67 75 69 5f 6c 6f 67 2e 74 78 74 } //2 imgui_log.txt
		$a_01_2 = {6b 4e 6f 54 4f 35 69 56 4c 47 } //2 kNoTO5iVLG
		$a_01_3 = {41 69 6d 62 6f 74 20 76 36 20 3a 20 49 6e 6a 65 63 74 65 64 21 } //2 Aimbot v6 : Injected!
		$a_01_4 = {53 41 4b 49 42 20 43 48 45 41 54 2e 70 64 62 } //2 SAKIB CHEAT.pdb
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2) >=10
 
}