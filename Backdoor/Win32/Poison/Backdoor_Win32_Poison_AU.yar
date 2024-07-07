
rule Backdoor_Win32_Poison_AU{
	meta:
		description = "Backdoor:Win32/Poison.AU,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_03_0 = {eb d4 be e0 03 00 00 8d 87 90 01 04 56 50 ff 77 90 01 01 e8 90 01 04 56 ff 77 90 01 01 e8 90 01 04 8b c6 eb 03 90 00 } //1
		$a_03_1 = {41 ad 03 c5 33 db 0f be 10 38 f2 74 08 c1 cb 90 01 01 03 da 40 eb f1 90 00 } //1
		$a_03_2 = {8b f5 8b fd b9 90 01 04 81 e9 90 01 04 ac 34 90 01 01 aa e2 fa 90 00 } //1
		$a_03_3 = {75 13 68 30 75 00 00 ff 95 90 01 04 ff 85 90 01 04 eb c7 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1) >=3
 
}