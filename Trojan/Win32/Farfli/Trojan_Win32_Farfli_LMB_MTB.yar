
rule Trojan_Win32_Farfli_LMB_MTB{
	meta:
		description = "Trojan:Win32/Farfli.LMB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 02 00 00 "
		
	strings :
		$a_01_0 = {80 c2 36 30 14 19 8b 4d 0c f7 e3 41 c1 ea 03 8d 04 92 33 d2 03 c0 3b d8 0f 45 d1 43 89 55 0c 3b df } //20
		$a_01_1 = {80 c2 36 30 14 19 8b 4d 0c f7 e3 41 c1 ea 03 8d 04 92 33 d2 03 c0 3b d8 0f 45 d1 43 } //10
	condition:
		((#a_01_0  & 1)*20+(#a_01_1  & 1)*10) >=30
 
}