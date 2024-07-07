
rule Trojan_BAT_AgentTesla_MD_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 05 00 00 "
		
	strings :
		$a_03_0 = {16 0d 2b 26 06 09 08 09 08 8e 69 5d 91 07 09 91 61 d2 6f 90 01 03 0a 09 13 04 2b 03 0c 2b e1 11 04 17 58 0d 2b 04 2c 0f 2b c5 09 07 8e 69 32 02 2b 05 90 00 } //10
		$a_01_1 = {44 6f 77 6e 6c 6f 61 64 44 61 74 61 } //1 DownloadData
		$a_01_2 = {54 6f 41 72 72 61 79 } //1 ToArray
		$a_01_3 = {47 65 74 42 79 74 65 73 } //1 GetBytes
		$a_01_4 = {49 6e 76 6f 6b 65 } //1 Invoke
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=14
 
}
rule Trojan_BAT_AgentTesla_MD_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.MD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 05 00 00 "
		
	strings :
		$a_00_0 = {01 57 1f a2 0b 09 1f 00 00 00 fa 01 33 00 16 00 00 01 00 00 00 6f 00 00 00 66 00 00 00 a3 00 00 00 9b 01 } //3
		$a_81_1 = {54 77 69 74 44 75 65 6c } //3 TwitDuel
		$a_81_2 = {50 72 69 63 65 27 73 20 45 6c 65 63 74 72 6f 6e 69 63 73 } //3 Price's Electronics
		$a_81_3 = {69 72 6f 6e 74 77 69 74 2f 74 72 65 65 2f 6d 61 73 74 65 72 } //3 irontwit/tree/master
		$a_81_4 = {54 68 69 73 20 69 73 20 72 65 61 6c 6c 79 20 42 41 44 21 } //3 This is really BAD!
	condition:
		((#a_00_0  & 1)*3+(#a_81_1  & 1)*3+(#a_81_2  & 1)*3+(#a_81_3  & 1)*3+(#a_81_4  & 1)*3) >=15
 
}