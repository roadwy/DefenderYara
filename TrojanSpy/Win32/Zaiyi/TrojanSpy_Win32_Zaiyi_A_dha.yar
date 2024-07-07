
rule TrojanSpy_Win32_Zaiyi_A_dha{
	meta:
		description = "TrojanSpy:Win32/Zaiyi.A!dha,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {68 65 69 7a 61 69 32 30 31 31 } //1 heizai2011
		$a_01_1 = {73 76 63 62 72 32 33 34 35 } //1 svcbr2345
		$a_01_2 = {74 31 31 32 30 } //1 t1120
		$a_01_3 = {63 72 65 61 74 20 72 61 6e 64 6f 6d 20 66 69 6c 65 6e 61 6d 65 21 } //1 creat random filename!
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}