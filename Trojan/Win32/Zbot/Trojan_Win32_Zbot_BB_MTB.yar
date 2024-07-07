
rule Trojan_Win32_Zbot_BB_MTB{
	meta:
		description = "Trojan:Win32/Zbot.BB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_02_0 = {48 43 35 00 59 00 00 47 83 ee ff 81 f1 90 01 04 49 41 e9 2e 90 00 } //5
		$a_02_1 = {84 00 43 00 8b 0d 90 01 04 8b 35 90 01 04 33 ce 89 35 90 01 04 8b 15 90 01 04 f7 da 89 15 90 01 04 8b 0d 90 01 04 81 e1 90 01 04 81 f1 90 01 04 49 89 0d 90 00 } //5
	condition:
		((#a_02_0  & 1)*5+(#a_02_1  & 1)*5) >=10
 
}