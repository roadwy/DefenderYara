
rule Trojan_Win32_Zenpak_ASAP_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.ASAP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {55 89 e5 56 8a 45 0c 8a 4d 08 88 c2 02 15 ?? ?? ?? 10 88 15 ?? ?? ?? 10 88 0d ?? ?? ?? 10 a2 ?? ?? ?? 10 30 c8 8b 35 ?? ?? ?? 10 81 c6 [0-04] 89 35 ?? ?? ?? 10 c7 05 [0-08] 0f b6 c0 5e 5d c3 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}