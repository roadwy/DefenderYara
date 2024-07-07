
rule Trojan_Win64_CobaltStrike_LKV_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.LKV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {31 00 32 00 34 00 2e 00 37 00 30 00 2e 00 31 00 38 00 39 00 2e 00 38 00 38 00 3a 00 38 00 30 00 38 00 30 00 2f 00 90 02 0f 2e 00 65 00 78 00 65 00 90 00 } //1
		$a_03_1 = {70 65 6c 6f 61 64 65 72 5c 70 65 6c 6f 61 64 65 72 5f 36 34 5c 90 02 0f 5c 52 65 6c 65 61 73 65 5c 70 65 6c 6f 61 64 65 72 90 02 0f 2e 70 64 62 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}