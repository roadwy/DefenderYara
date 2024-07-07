
rule Trojan_BAT_Redline_NEAP_MTB{
	meta:
		description = "Trojan:BAT/Redline.NEAP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 02 00 00 "
		
	strings :
		$a_01_0 = {00 7e 0a 00 00 04 17 9a 28 34 00 00 0a 28 35 00 00 0a 28 36 00 00 0a 28 1c 00 00 06 80 0b 00 00 04 7e 0f 00 00 04 7e 0a 00 00 04 18 9a 28 37 00 00 0a 28 34 00 00 0a 7e 0b 00 00 04 28 38 00 00 0a 00 14 d0 2f 00 00 01 28 28 00 00 0a 72 41 00 00 70 17 8d 17 00 00 01 25 16 7e 0f 00 00 04 7e 0a 00 00 04 18 9a 28 37 00 00 0a a2 14 14 14 17 28 39 00 00 0a 26 2a } //10
		$a_01_1 = {42 46 52 2e 65 78 65 } //2 BFR.exe
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*2) >=12
 
}