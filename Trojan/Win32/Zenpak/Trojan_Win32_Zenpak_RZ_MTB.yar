
rule Trojan_Win32_Zenpak_RZ_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.RZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8a 04 32 8b 55 f8 02 c2 8b 55 08 32 04 0a 88 01 41 83 6d 0c 01 89 4d 18 75 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}