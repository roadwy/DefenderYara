
rule Trojan_Win64_Mikey_SXE_MTB{
	meta:
		description = "Trojan:Win64/Mikey.SXE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,28 00 28 00 03 00 00 "
		
	strings :
		$a_03_0 = {8b c1 48 c1 e8 06 83 e0 0f 0f b6 44 04 40 88 05 ?? ?? ?? ?? 8b c1 48 c1 e8 08 83 e0 0f } //20
		$a_80_1 = {2f 73 74 61 74 69 63 2f 62 6f 6f 74 73 74 72 61 70 2e 63 73 73 } ///static/bootstrap.css  10
		$a_80_2 = {2f 61 73 73 65 74 73 2f 6a 71 75 65 72 79 2d 33 2e 36 2e 30 2e 6d 69 6e 2e 6a 73 } ///assets/jquery-3.6.0.min.js  10
	condition:
		((#a_03_0  & 1)*20+(#a_80_1  & 1)*10+(#a_80_2  & 1)*10) >=40
 
}