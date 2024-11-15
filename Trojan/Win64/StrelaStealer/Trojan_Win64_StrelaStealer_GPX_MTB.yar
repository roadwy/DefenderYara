
rule Trojan_Win64_StrelaStealer_GPX_MTB{
	meta:
		description = "Trojan:Win64/StrelaStealer.GPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 03 00 00 "
		
	strings :
		$a_01_0 = {41 b8 00 30 00 00 41 b9 40 00 00 00 31 c9 ff d0 48 89 44 24 } //2
		$a_01_1 = {4c 01 e8 48 05 04 04 00 00 48 89 } //5
		$a_01_2 = {45 6e 74 72 79 00 } //1 湅牴y
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*5+(#a_01_2  & 1)*1) >=8
 
}
rule Trojan_Win64_StrelaStealer_GPX_MTB_2{
	meta:
		description = "Trojan:Win64/StrelaStealer.GPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 03 00 00 "
		
	strings :
		$a_01_0 = {8a 10 89 d1 f6 d1 89 c8 41 89 c8 88 8d 00 } //5
		$a_01_1 = {40 30 f1 08 d1 89 ca 80 f2 01 20 d1 89 d3 20 cb 30 d1 08 d9 } //2
		$a_01_2 = {45 6e 74 72 79 00 } //1 湅牴y
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1) >=8
 
}