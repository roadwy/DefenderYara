
rule Trojan_Win32_Zenpak_RN_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.RN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {55 89 e5 56 50 8a 45 90 01 01 8a 4d 90 01 01 88 45 90 01 01 88 4d 90 01 01 c7 05 90 01 08 0f b6 55 90 01 01 0f b6 75 90 01 01 31 f2 88 d0 a2 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}