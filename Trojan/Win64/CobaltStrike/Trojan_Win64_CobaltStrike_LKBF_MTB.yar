
rule Trojan_Win64_CobaltStrike_LKBF_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.LKBF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {55 73 65 72 73 5c 41 70 6f 63 61 6c 79 70 73 65 5c [0-80] 5c 52 75 73 74 5c 63 6c 69 65 6e 74 5c 31 2e 70 64 62 } //1
		$a_01_1 = {35 37 6b 37 77 32 68 64 35 32 2e 38 70 66 79 68 2e 77 73 3a 38 34 34 33 2f 54 73 65 4e 6e 37 } //1 57k7w2hd52.8pfyh.ws:8443/TseNn7
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}