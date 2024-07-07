
rule Trojan_Win32_Ranumbot_GE_MTB{
	meta:
		description = "Trojan:Win32/Ranumbot.GE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b cf c1 e9 90 01 01 c7 05 90 01 08 c7 05 90 01 04 ff ff ff ff 89 4c 24 90 01 01 8b 84 24 90 01 04 01 44 24 90 01 01 8b 4c 24 90 01 01 33 cb 33 ce 8d 84 24 90 01 04 e8 90 01 04 81 c5 90 01 04 83 ac 24 90 01 04 01 0f 85 90 00 } //10
	condition:
		((#a_02_0  & 1)*10) >=10
 
}