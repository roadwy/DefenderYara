
rule Trojan_Win32_Stealer_GPAD_MTB{
	meta:
		description = "Trojan:Win32/Stealer.GPAD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_03_0 = {c7 45 f8 00 00 00 00 c7 45 fc 00 00 00 00 c7 45 fc 00 00 00 00 eb 09 8b 45 fc 83 c0 01 89 45 fc 81 7d fc ?? ?? ?? ?? 7d 0b 8b 4d f8 83 c1 01 89 4d f8 eb e3 } //4
	condition:
		((#a_03_0  & 1)*4) >=4
 
}