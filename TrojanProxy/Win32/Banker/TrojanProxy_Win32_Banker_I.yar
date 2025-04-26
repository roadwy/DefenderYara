
rule TrojanProxy_Win32_Banker_I{
	meta:
		description = "TrojanProxy:Win32/Banker.I,SIGNATURE_TYPE_PEHSTR_EXT,ffffff82 00 6e 00 03 00 00 "
		
	strings :
		$a_01_0 = {6d 79 73 74 65 72 79 69 6e 73 63 61 72 6c 65 74 63 69 74 79 2e 63 6f 6d 2f 2f 6d 6f 64 75 6c 65 73 2f 6d 6f 64 5f 63 62 6c 6f 67 69 6e 2f 6d 6f 64 5f 63 62 6c 6f 67 69 6e 2e 68 74 6d 6c } //100 mysteryinscarletcity.com//modules/mod_cblogin/mod_cblogin.html
		$a_01_1 = {5a 50 42 43 5a 44 5f 1b 46 46 5a 4e 4d 1b } //20
		$a_01_2 = {44 47 53 52 46 18 5e 46 00 } //10
	condition:
		((#a_01_0  & 1)*100+(#a_01_1  & 1)*20+(#a_01_2  & 1)*10) >=110
 
}