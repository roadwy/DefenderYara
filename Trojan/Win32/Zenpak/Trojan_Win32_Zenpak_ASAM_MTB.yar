
rule Trojan_Win32_Zenpak_ASAM_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.ASAM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {55 89 e5 8a 45 0c 8a 4d 08 88 c2 30 ca 88 0d ?? ?? ?? ?? a2 ?? ?? ?? ?? 88 15 ?? ?? ?? ?? c7 05 [0-08] c7 05 [0-08] 0f b6 c2 5d c3 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}