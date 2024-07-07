
rule Trojan_Win32_Zenpak_KAL_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.KAL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {55 89 e5 8a 45 0c 8a 4d 08 8b 15 90 01 04 c7 05 90 01 08 81 c2 90 01 04 89 15 90 01 04 30 c8 0f b6 c0 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}