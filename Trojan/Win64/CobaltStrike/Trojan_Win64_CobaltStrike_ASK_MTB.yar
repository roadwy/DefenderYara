
rule Trojan_Win64_CobaltStrike_ASK_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.ASK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_01_0 = {45 8a 34 11 44 30 34 0f 48 ff c1 48 89 c8 48 81 f9 ff c5 06 00 0f } //4
		$a_01_1 = {48 31 44 5e 33 68 40 76 45 59 5e 62 70 29 4c 55 67 6c } //1 H1D^3h@vEY^bp)LUgl
	condition:
		((#a_01_0  & 1)*4+(#a_01_1  & 1)*1) >=5
 
}