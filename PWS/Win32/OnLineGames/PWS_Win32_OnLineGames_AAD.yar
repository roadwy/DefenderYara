
rule PWS_Win32_OnLineGames_AAD{
	meta:
		description = "PWS:Win32/OnLineGames.AAD,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_02_0 = {4d 5a 52 ff 25 90 01 02 40 00 90 00 } //1
		$a_00_1 = {36 30 73 61 66 65 } //1 60safe
		$a_00_2 = {4b 56 4d 6f 6e 58 50 } //1 KVMonXP
		$a_00_3 = {27 63 6d 64 20 2f 63 20 25 73 } //1 'cmd /c %s
	condition:
		((#a_02_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}