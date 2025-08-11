
rule Trojan_Win32_Injector_PAQD_MTB{
	meta:
		description = "Trojan:Win32/Injector.PAQD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 55 fc 8b 32 33 c0 85 f6 7e ?? 8b 55 08 8a 14 10 30 14 07 40 3b c6 7c ?? 83 45 fc 04 83 c7 19 81 7d fc } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}