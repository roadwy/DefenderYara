
rule Trojan_Win64_Qakbot_YAT_MTB{
	meta:
		description = "Trojan:Win64/Qakbot.YAT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {63 75 72 6c 20 68 74 74 70 3a 2f 2f 31 33 35 2e 31 32 35 2e 31 37 37 2e 39 34 2f [0-09] 2e 64 61 74 20 2d 6f } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}