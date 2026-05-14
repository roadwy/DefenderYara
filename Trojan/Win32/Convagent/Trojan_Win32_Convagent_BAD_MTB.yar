
rule Trojan_Win32_Convagent_BAD_MTB{
	meta:
		description = "Trojan:Win32/Convagent.BAD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {41 8b 45 08 03 45 f8 0f b6 10 33 94 8d ?? ?? ?? ?? 8b 45 08 03 45 f8 88 10 e9 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}
rule Trojan_Win32_Convagent_BAD_MTB_2{
	meta:
		description = "Trojan:Win32/Convagent.BAD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {8a 0c 32 80 f9 64 77 ?? b0 64 eb ?? 80 f9 c8 b0 2d 76 ?? b0 c8 2a c1 88 04 32 42 3b d7 72 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}
rule Trojan_Win32_Convagent_BAD_MTB_3{
	meta:
		description = "Trojan:Win32/Convagent.BAD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b6 45 fe 03 c2 88 45 ?? 0f b6 4d ?? 8b 55 ?? 2b d1 89 55 ?? 0f b6 45 ?? 03 05 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}