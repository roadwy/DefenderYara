
rule Trojan_Win64_Convagent_MX_MTB{
	meta:
		description = "Trojan:Win64/Convagent.MX!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {48 89 78 10 48 c7 40 18 0f 00 00 00 40 88 38 48 8d 54 24 40 66 48 0f 7e c1 66 0f 6f c1 66 0f 73 d8 08 66 48 0f 7e c0 48 83 f8 0f 48 0f 47 d1 66 49 0f 7e c8 48 8d 8d 50 01 } //1
		$a_01_1 = {64 69 73 63 6f 72 64 2e 63 6f 6d 2f 61 70 69 2f 77 65 62 68 6f 6f 6b 73 } //1 discord.com/api/webhooks
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}