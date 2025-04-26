
rule Trojan_Win32_Pubavid_B{
	meta:
		description = "Trojan:Win32/Pubavid.B,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {c6 00 e9 ff 06 8b 06 2b d8 8d 4c 3b fc 89 08 83 c8 ff 2b c7 5f 01 06 } //1
		$a_03_1 = {8a 04 02 30 01 46 3b (74|75) [0-03] 7e } //1
		$a_00_2 = {42 41 56 31 44 4c 4c 2e 64 6c 6c 00 } //1 䅂ㅖ䱄⹌汤l
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}