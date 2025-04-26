
rule Trojan_Win32_StartPage_PVW_bit{
	meta:
		description = "Trojan:Win32/StartPage.PVW!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {54 00 72 00 6f 00 6a 00 61 00 6e 00 52 00 75 00 6e 00 54 00 69 00 6d 00 65 00 72 00 } //1 TrojanRunTimer
		$a_01_1 = {45 00 76 00 65 00 6e 00 74 00 46 00 69 00 6c 00 74 00 65 00 72 00 2e 00 6e 00 61 00 6d 00 65 00 20 00 3d 00 20 00 54 00 72 00 6f 00 6a 00 61 00 6e 00 4e 00 61 00 6d 00 65 00 20 00 26 00 20 00 22 00 5f 00 66 00 69 00 6c 00 74 00 65 00 72 00 22 00 } //1 EventFilter.name = TrojanName & "_filter"
		$a_01_2 = {46 00 6f 00 72 00 20 00 45 00 61 00 63 00 68 00 20 00 62 00 72 00 6f 00 77 00 73 00 65 00 72 00 20 00 49 00 6e 00 20 00 62 00 72 00 6f 00 77 00 73 00 65 00 72 00 73 00 41 00 72 00 72 00 } //1 For Each browser In browsersArr
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}