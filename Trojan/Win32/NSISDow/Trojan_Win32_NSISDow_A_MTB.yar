
rule Trojan_Win32_NSISDow_A_MTB{
	meta:
		description = "Trojan:Win32/NSISDow.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 05 00 00 "
		
	strings :
		$a_01_0 = {74 67 62 6e 68 79 68 74 67 62 6e 68 79 74 74 67 62 6e 68 79 74 74 67 62 6e 68 79 70 74 67 62 6e 68 79 3a 74 67 62 6e 68 79 2f 74 67 62 6e 68 79 2f 74 67 62 6e 68 79 77 74 67 62 6e 68 79 77 74 67 62 6e 68 79 77 74 67 62 6e 68 79 2e 74 67 62 6e 68 79 } //2 tgbnhyhtgbnhyttgbnhyttgbnhyptgbnhy:tgbnhy/tgbnhy/tgbnhywtgbnhywtgbnhywtgbnhy.tgbnhy
		$a_01_1 = {2f 75 73 65 72 61 67 65 6e 74 } //2 /useragent
		$a_01_2 = {2f 4e 4f 50 52 4f 58 59 } //2 /NOPROXY
		$a_01_3 = {53 4f 46 54 57 41 52 45 5c 42 6f 74 68 61 } //2 SOFTWARE\Botha
		$a_01_4 = {39 6b 68 73 6f 38 32 6e } //2 9khso82n
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2) >=10
 
}