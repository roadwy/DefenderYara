
rule Trojan_Win32_Zenpak_CCIE_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.CCIE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {56 50 8a 45 ?? 8a 4d ?? 88 45 ?? 88 4d ?? 0f b6 55 ?? 0f b6 75 ?? 31 f2 88 d0 a2 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}