
rule Trojan_Win32_Convagent_BAD_MTB{
	meta:
		description = "Trojan:Win32/Convagent.BAD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b6 45 fe 03 c2 88 45 ?? 0f b6 4d ?? 8b 55 ?? 2b d1 89 55 ?? 0f b6 45 ?? 03 05 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}