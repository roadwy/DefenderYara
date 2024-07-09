
rule Trojan_Win32_Kryptik_RA_MTB{
	meta:
		description = "Trojan:Win32/Kryptik.RA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {0f b6 c8 8b 55 ?? 03 55 ?? 0f be 02 33 c1 8b 4d ?? 03 4d ?? 88 01 8b 55 ?? 83 ea 01 89 55 ?? eb } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}