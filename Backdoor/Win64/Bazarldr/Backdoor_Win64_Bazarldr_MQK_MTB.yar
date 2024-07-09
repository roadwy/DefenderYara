
rule Backdoor_Win64_Bazarldr_MQK_MTB{
	meta:
		description = "Backdoor:Win64/Bazarldr.MQK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 44 24 24 99 41 f7 7e [0-01] 48 8b 07 48 63 4c 24 [0-01] 8a 04 08 49 8b 36 48 63 d2 8a 1c 16 89 da 44 30 ca 20 c2 44 30 c8 20 d8 08 d0 48 8b 54 24 [0-01] 48 8b 12 88 04 0a 8b 44 24 [0-01] ff c0 eb } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}