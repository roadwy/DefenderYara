
rule Backdoor_Win32_Bitsto_A{
	meta:
		description = "Backdoor:Win32/Bitsto.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 03 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {67 65 74 20 75 73 65 72 20 6e 61 6d 65 20 65 72 72 6f 72 21 } //01 00  get user name error!
		$a_01_1 = {00 66 69 6c 65 75 70 6c 6f 61 64 00 } //01 00  昀汩略汰慯d
		$a_01_2 = {6d 61 63 68 69 6e 65 20 74 79 70 65 3a 20 6d 61 79 62 65 20 70 63 } //01 00  machine type: maybe pc
		$a_01_3 = {52 75 6e 64 6c 6c 49 6e 73 74 61 6c 6c 41 00 52 75 6e 64 6c 6c 55 6e 69 6e 73 74 61 6c 6c 41 00 } //01 00  畒摮汬湉瑳污䅬刀湵汤啬楮獮慴汬A
		$a_00_4 = {8a 0c 2a 8b c2 2b c6 8b fd 42 88 4c 18 ff 83 c9 ff 33 c0 } //00 00 
	condition:
		any of ($a_*)
 
}