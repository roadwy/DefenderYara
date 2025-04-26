
rule PWS_Win32_OnLineGames_KG{
	meta:
		description = "PWS:Win32/OnLineGames.KG,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {47 55 49 44 5f 53 79 73 4b 65 79 62 6f 61 72 64 } //1 GUID_SysKeyboard
		$a_01_1 = {53 48 45 4c 4c 48 4f 4f 4b } //1 SHELLHOOK
		$a_01_2 = {2f 63 20 64 65 6c } //1 /c del
		$a_01_3 = {5c 00 44 00 4e 00 46 00 } //1 \DNF
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}