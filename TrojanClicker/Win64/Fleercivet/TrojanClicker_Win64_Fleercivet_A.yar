
rule TrojanClicker_Win64_Fleercivet_A{
	meta:
		description = "TrojanClicker:Win64/Fleercivet.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {25 73 5c 40 73 79 73 74 65 6d 32 2e 61 74 74 } //1 %s\@system2.att
		$a_01_1 = {46 65 65 64 3a 20 00 00 00 00 00 00 2c 20 6d 61 78 3a 20 00 2c 20 63 6f 75 6e 74 3a 20 00 00 00 63 74 63 00 63 65 72 00 63 73 00 00 2a 2e 2a } //1
		$a_01_2 = {21 00 49 00 45 00 54 00 6c 00 64 00 21 00 4d 00 75 00 74 00 65 00 78 00 5f 00 25 00 64 00 } //1 !IETld!Mutex_%d
		$a_01_3 = {00 63 6c 69 63 6b 65 72 36 34 2e 64 6c 6c 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}