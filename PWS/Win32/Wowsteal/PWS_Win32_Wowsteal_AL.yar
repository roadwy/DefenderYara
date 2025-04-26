
rule PWS_Win32_Wowsteal_AL{
	meta:
		description = "PWS:Win32/Wowsteal.AL,SIGNATURE_TYPE_PEHSTR,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {61 63 74 69 6f 6e 3d 64 6f 6d 6f 64 26 7a 74 3d } //1 action=domod&zt=
		$a_01_1 = {64 61 74 61 5c 65 6e 55 53 5c 72 65 61 6c 6d 6c 69 73 74 2e 77 74 66 } //1 data\enUS\realmlist.wtf
		$a_01_2 = {61 63 74 69 6f 6e 3d 6f 6b 26 75 3d } //1 action=ok&u=
		$a_01_3 = {2f 77 6f 77 52 65 61 64 4d 62 2e 61 73 70 } //1 /wowReadMb.asp
		$a_01_4 = {2f 6c 6f 67 69 6e 69 70 2e 61 73 70 } //1 /loginip.asp
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}