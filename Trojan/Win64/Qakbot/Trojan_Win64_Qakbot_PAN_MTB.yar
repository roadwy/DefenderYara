
rule Trojan_Win64_Qakbot_PAN_MTB{
	meta:
		description = "Trojan:Win64/Qakbot.PAN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {62 75 73 69 6e 65 73 73 2e 64 6f 63 } //1 business.doc
		$a_01_1 = {3a 2f 2f 00 50 4f 53 54 } //1 ⼺/佐呓
		$a_01_2 = {65 6e 64 6c 65 73 73 00 61 70 70 65 61 72 } //1 湥汤獥s灡数牡
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}