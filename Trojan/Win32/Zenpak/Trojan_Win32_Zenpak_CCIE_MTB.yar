
rule Trojan_Win32_Zenpak_CCIE_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.CCIE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {56 50 8a 45 90 01 01 8a 4d 90 01 01 88 45 90 01 01 88 4d 90 01 01 0f b6 55 90 01 01 0f b6 75 90 01 01 31 f2 88 d0 a2 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}