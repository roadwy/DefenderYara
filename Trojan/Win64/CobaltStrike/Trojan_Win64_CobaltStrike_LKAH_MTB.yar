
rule Trojan_Win64_CobaltStrike_LKAH_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.LKAH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {41 b9 40 00 00 00 41 b8 00 10 00 00 49 90 01 02 33 90 01 01 ff 90 00 } //1
		$a_01_1 = {48 83 ec 28 b9 6b cc b4 a7 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}