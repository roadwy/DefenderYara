
rule Trojan_Win64_Tedy_KKF_MTB{
	meta:
		description = "Trojan:Win64/Tedy.KKF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 02 00 00 "
		
	strings :
		$a_01_0 = {89 c2 c1 e2 05 01 d0 41 0f b6 14 0a 31 d0 88 04 0b 48 83 c1 01 48 83 f9 20 } //20
		$a_01_1 = {45 0f b6 04 01 45 30 04 06 48 83 c0 01 48 39 d0 75 ee } //10
	condition:
		((#a_01_0  & 1)*20+(#a_01_1  & 1)*10) >=30
 
}