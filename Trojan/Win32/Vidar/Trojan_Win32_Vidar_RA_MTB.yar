
rule Trojan_Win32_Vidar_RA_MTB{
	meta:
		description = "Trojan:Win32/Vidar.RA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {99 f7 fe 8b 45 90 01 01 0f be 0c 11 83 e1 90 01 01 81 e1 90 01 04 31 c8 88 45 90 01 01 0f be 45 90 01 01 0f be 4d 90 01 01 01 c8 88 c2 8b 45 90 01 01 8b 4d 90 01 01 88 14 08 0f be 75 90 01 01 8b 45 90 01 01 8b 4d 90 01 01 0f be 14 08 29 f2 88 14 08 8b 45 90 01 01 83 c0 01 89 45 90 01 01 e9 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}