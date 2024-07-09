
rule Backdoor_Win32_Zegost_DO{
	meta:
		description = "Backdoor:Win32/Zegost.DO,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_03_0 = {2b c8 8a 14 01 80 f2 ?? 88 10 40 4b 75 f4 } //1
		$a_01_1 = {53 83 c3 00 83 c3 00 83 c4 0a 83 ec 0a 83 c3 00 83 c3 00 32 c0 5b c3 } //2
		$a_01_2 = {3c 48 31 3e 34 30 33 20 46 6f 72 62 69 64 64 65 6e 3c 2f 48 31 3e } //1 <H1>403 Forbidden</H1>
		$a_01_3 = {52 44 50 2d 54 63 70 00 25 64 44 61 79 20 25 64 48 6f 75 72 20 25 64 4d 69 6e } //1 䑒ⵐ捔p搥慄⁹搥潈牵┠䵤湩
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=5
 
}