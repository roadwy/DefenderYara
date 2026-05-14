
rule Trojan_Win64_Rozena_AHD_MTB{
	meta:
		description = "Trojan:Win64/Rozena.AHD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,32 00 32 00 03 00 00 "
		
	strings :
		$a_03_0 = {33 c2 2b c2 48 98 48 8b [0-06] 0f be 04 01 8b [0-06] 33 c8 8b c1 48 63 4c 24 20 48 8b [0-06] 88 04 0a eb } //30
		$a_01_1 = {48 63 4c 24 20 48 89 44 cc 50 48 63 44 24 20 48 8b 44 c4 50 48 89 44 24 40 c7 44 24 24 00 00 00 00 eb } //20
		$a_01_2 = {c6 44 24 53 65 c6 44 24 54 73 c6 44 24 55 73 c6 44 24 56 00 48 8d 54 24 48 48 8b 8c 24 88 } //20
	condition:
		((#a_03_0  & 1)*30+(#a_01_1  & 1)*20+(#a_01_2  & 1)*20) >=50
 
}