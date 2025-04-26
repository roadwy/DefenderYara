
rule Trojan_Win64_CobaltStrike_PACC_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.PACC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {49 63 c9 f0 80 34 19 39 41 ff c1 44 3b ce 72 f0 } //1
		$a_01_1 = {50 00 41 00 59 00 4c 00 4f 00 41 00 44 00 5f 00 42 00 49 00 4e 00 } //1 PAYLOAD_BIN
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}