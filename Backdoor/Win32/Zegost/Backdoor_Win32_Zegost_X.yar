
rule Backdoor_Win32_Zegost_X{
	meta:
		description = "Backdoor:Win32/Zegost.X,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {50 43 52 61 74 00 } //1 䍐慒t
		$a_01_1 = {4c 41 4e 47 3a 25 64 7c 57 69 6e 20 25 73 7c 25 73 7c 25 73 } //2 LANG:%d|Win %s|%s|%s
		$a_03_2 = {47 45 54 20 2f 68 2e 67 69 66 3f 70 69 64 20 3d [0-05] 26 76 3d } //2
		$a_01_3 = {47 6c 6f 62 61 6c 5c 47 68 30 73 74 } //2 Global\Gh0st
		$a_01_4 = {53 74 6f 72 6d 20 64 64 6f 73 20 73 6f 66 74 } //1 Storm ddos soft
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*2+(#a_03_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*1) >=5
 
}