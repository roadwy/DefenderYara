
rule Trojan_Win64_IcedID_DP_MTB{
	meta:
		description = "Trojan:Win64/IcedID.DP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 0f 00 00 0a 00 "
		
	strings :
		$a_01_0 = {36 31 67 77 77 62 32 37 2e 64 6c 6c } //01 00  61gwwb27.dll
		$a_01_1 = {48 76 73 48 55 74 78 78 4e } //01 00  HvsHUtxxN
		$a_01_2 = {69 68 6e 7a 57 4f 75 31 59 4d 38 } //01 00  ihnzWOu1YM8
		$a_01_3 = {76 53 50 68 6b 52 4c 49 53 50 38 } //01 00  vSPhkRLISP8
		$a_01_4 = {55 68 41 70 58 37 45 45 74 } //0a 00  UhApX7EEt
		$a_01_5 = {4e 43 77 58 64 71 61 4e 2e 64 6c 6c } //01 00  NCwXdqaN.dll
		$a_01_6 = {43 66 45 71 70 43 6c 7a 6f 4f } //01 00  CfEqpClzoO
		$a_01_7 = {45 49 53 38 59 49 48 31 73 61 45 } //01 00  EIS8YIH1saE
		$a_01_8 = {45 6a 37 55 41 77 68 6b 47 36 67 } //01 00  Ej7UAwhkG6g
		$a_01_9 = {51 34 76 62 6c 34 6a 63 34 38 4d } //0a 00  Q4vbl4jc48M
		$a_01_10 = {55 72 69 71 37 32 55 6d 2e 64 6c 6c } //01 00  Uriq72Um.dll
		$a_01_11 = {48 48 4f 44 6a 62 33 42 } //01 00  HHODjb3B
		$a_01_12 = {49 44 52 4e 52 4d 62 } //01 00  IDRNRMb
		$a_01_13 = {52 4f 72 51 63 62 4e 37 34 36 } //01 00  ROrQcbN746
		$a_01_14 = {62 79 5a 49 48 4c 71 72 4a } //00 00  byZIHLqrJ
	condition:
		any of ($a_*)
 
}