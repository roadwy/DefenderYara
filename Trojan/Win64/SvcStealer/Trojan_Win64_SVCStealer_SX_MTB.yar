
rule Trojan_Win64_SVCStealer_SX_MTB{
	meta:
		description = "Trojan:Win64/SVCStealer.SX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,23 00 23 00 03 00 00 "
		
	strings :
		$a_03_0 = {0f be 37 8b ce e8 ?? ?? ?? ?? 85 c0 75 09 40 80 fe 5f 74 03 c6 07 5f 48 ff c7 48 3b fb 75 e1 } //20
		$a_03_1 = {4c 89 7c 24 38 4c 89 7c 24 30 44 89 7c 24 28 4c 89 7c 24 20 41 83 c9 ff 33 d2 33 c9 ff 15 ?? ?? ?? ?? 48 63 f8 48 c7 44 24 78 0f 00 00 00 4c 89 7c 24 70 44 88 7c 24 60 48 8b d7 45 33 c0 48 8d 4c 24 60 e8 } //10
		$a_81_2 = {39 41 50 41 52 57 38 33 5a 36 } //5 9APARW83Z6
	condition:
		((#a_03_0  & 1)*20+(#a_03_1  & 1)*10+(#a_81_2  & 1)*5) >=35
 
}