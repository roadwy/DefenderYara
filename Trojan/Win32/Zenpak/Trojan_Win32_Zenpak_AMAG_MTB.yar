
rule Trojan_Win32_Zenpak_AMAG_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.AMAG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {55 89 e5 56 8a 45 0c 8a 4d 08 88 c2 02 15 ?? ?? ?? ?? 88 15 ?? ?? ?? ?? 8b 35 ?? ?? ?? ?? 81 c6 ?? ?? ?? ?? 89 35 ?? ?? ?? ?? 88 0d ?? ?? ?? ?? a2 ?? ?? ?? ?? 30 c8 0f b6 c0 5e 5d c3 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}