
rule Trojan_Win32_Convagent_RPX_MTB{
	meta:
		description = "Trojan:Win32/Convagent.RPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {60 e8 00 00 00 00 5d 50 51 0f ca f7 d2 9c f7 d2 0f ca eb 0f b9 eb 0f b8 eb 07 b9 eb 0f 90 eb 08 fd eb 0b f2 eb f5 eb f6 f2 eb 08 fd } //1
		$a_01_1 = {67 00 6f 00 64 00 7a 00 6d 00 75 00 } //1 godzmu
		$a_01_2 = {4b 41 4d 45 52 73 55 43 4b 53 73 4b 41 4d 45 52 73 55 43 4b 53 } //1 KAMERsUCKSsKAMERsUCKS
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}