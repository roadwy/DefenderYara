
rule TrojanSpy_Win64_Derusbi_dha{
	meta:
		description = "TrojanSpy:Win64/Derusbi!dha,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {50 43 43 5f 43 4d 44 } //1 PCC_CMD
		$a_01_1 = {50 43 43 5f 46 49 4c 45 } //1 PCC_FILE
		$a_01_2 = {50 43 43 5f 50 52 4f 58 59 } //1 PCC_PROXY
		$a_01_3 = {72 00 75 00 6e 00 64 00 6c 00 6c 00 33 00 32 00 20 00 22 00 25 00 73 00 22 00 2c 00 20 00 52 00 75 00 6e 00 33 00 32 00 20 00 25 00 73 00 } //1 rundll32 "%s", Run32 %s
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}