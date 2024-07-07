
rule Trojan_Win32_Ranumbot_RMG_MTB{
	meta:
		description = "Trojan:Win32/Ranumbot.RMG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {b8 b7 59 e7 1f f7 a4 24 90 01 04 8b 84 24 90 01 04 81 44 24 90 01 01 f3 ae ac 68 81 ac 24 90 01 04 b3 30 c7 6b 81 84 24 90 01 04 21 f4 7c 36 30 0c 3e 56 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}