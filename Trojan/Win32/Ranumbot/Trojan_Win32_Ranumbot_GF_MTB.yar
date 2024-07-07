
rule Trojan_Win32_Ranumbot_GF_MTB{
	meta:
		description = "Trojan:Win32/Ranumbot.GF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b 4c 24 10 33 cf 33 ce 8d 84 24 90 01 04 e8 90 01 04 81 c3 90 01 04 83 ac 24 90 01 04 01 0f 85 90 0a 78 00 8b 90 01 01 c1 90 01 01 05 c7 05 90 01 08 c7 05 90 01 04 ff ff ff ff 89 90 00 } //10
	condition:
		((#a_02_0  & 1)*10) >=10
 
}