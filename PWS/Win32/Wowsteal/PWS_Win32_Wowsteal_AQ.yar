
rule PWS_Win32_Wowsteal_AQ{
	meta:
		description = "PWS:Win32/Wowsteal.AQ,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 07 00 00 "
		
	strings :
		$a_01_0 = {64 61 74 61 5c 7a 68 54 57 5c 72 65 61 6c 6d 6c 69 73 74 2e 77 74 66 } //1 data\zhTW\realmlist.wtf
		$a_00_1 = {61 63 74 69 6f 6e 3d 6f 6b 26 75 3d } //1 action=ok&u=
		$a_00_2 = {53 4f 46 54 57 41 52 45 5c 42 6c 69 7a 7a 61 72 64 20 45 6e 74 65 72 74 61 69 6e 6d 65 6e 74 5c 57 6f } //1 SOFTWARE\Blizzard Entertainment\Wo
		$a_00_3 = {44 69 76 78 44 65 63 6f 64 65 72 2e 64 6c 6c } //1 DivxDecoder.dll
		$a_00_4 = {2f 77 6f 77 52 65 61 64 4d 62 2e 61 73 } //1 /wowReadMb.as
		$a_01_5 = {50 50 68 60 9c 5b 00 56 89 44 24 } //3
		$a_01_6 = {51 51 68 e2 12 61 00 56 89 4c 24 } //3
	condition:
		((#a_01_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_01_5  & 1)*3+(#a_01_6  & 1)*3) >=5
 
}