
rule Trojan_Win64_Trickbot_RPX_MTB{
	meta:
		description = "Trojan:Win64/Trickbot.RPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {48 8b 4c 24 38 66 44 89 64 24 40 41 bc 01 00 00 00 c7 44 24 44 e1 07 01 00 c7 44 24 54 a0 05 00 00 66 44 89 64 24 48 44 89 64 24 58 44 89 64 24 60 66 44 89 64 24 64 48 8b 01 48 8d 54 24 40 ff 50 18 85 c0 0f 88 9d 00 00 00 48 8b 8d 88 00 00 00 66 89 5c 24 70 48 8d 54 24 70 48 8b 01 45 33 c0 ff 90 f0 00 00 00 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}