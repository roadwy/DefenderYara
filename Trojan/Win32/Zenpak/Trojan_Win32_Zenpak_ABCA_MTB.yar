
rule Trojan_Win32_Zenpak_ABCA_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.ABCA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {55 89 e5 8a 45 0c 8a 4d 08 8b 15 ?? ?? ?? ?? 88 c4 02 25 ?? ?? ?? ?? 88 25 ?? ?? ?? ?? 81 c2 ?? ?? ?? ?? 89 15 ?? ?? ?? ?? 88 0d ?? ?? ?? ?? a2 ?? ?? ?? ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 0f b6 c4 5d c3 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}