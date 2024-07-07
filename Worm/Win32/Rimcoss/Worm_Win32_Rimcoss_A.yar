
rule Worm_Win32_Rimcoss_A{
	meta:
		description = "Worm:Win32/Rimcoss.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {81 7c 24 04 00 00 80 3e 73 11 8b 44 24 00 85 c0 75 09 32 c0 } //1
		$a_01_1 = {74 47 8d 4c 24 14 8d 54 24 38 51 52 ff d7 85 c0 74 09 66 81 7c 24 14 d0 07 72 2e } //1
		$a_01_2 = {8b 54 24 08 6a 00 6a 00 68 19 02 00 00 52 ff 15 } //1
		$a_00_3 = {5b 41 75 74 6f 52 75 6e 5d 00 } //1 䅛瑵副湵]
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}