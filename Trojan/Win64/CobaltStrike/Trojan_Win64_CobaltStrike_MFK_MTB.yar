
rule Trojan_Win64_CobaltStrike_MFK_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.MFK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 03 00 00 "
		
	strings :
		$a_01_0 = {33 c9 53 0f a2 8b f3 5b 8d 5d dc } //1
		$a_03_1 = {8b c1 33 d2 f7 f6 8a 44 15 [0-01] 30 04 39 41 81 f9 [0-02] 00 00 7c } //10
		$a_03_2 = {6a 40 68 00 30 00 00 68 [0-02] 00 00 6a 00 ff 15 [0-04] 85 c0 74 0e 8b f7 b9 [0-02] 00 00 8b f8 f3 a5 a4 ff d0 } //10
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*10+(#a_03_2  & 1)*10) >=11
 
}