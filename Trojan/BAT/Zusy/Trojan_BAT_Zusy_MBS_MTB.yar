
rule Trojan_BAT_Zusy_MBS_MTB{
	meta:
		description = "Trojan:BAT/Zusy.MBS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_01_0 = {13 10 00 72 fc f8 01 70 11 10 } //1
		$a_01_1 = {13 12 11 12 14 fe 03 } //1
		$a_01_2 = {58 53 50 43 6e 78 4f 33 4a 35 65 4b 67 72 62 51 33 52 2e 37 6c 6a 62 4e 70 64 62 50 54 37 } //2 XSPCnxO3J5eKgrbQ3R.7ljbNpdbPT7
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*2) >=4
 
}