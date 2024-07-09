
rule Trojan_Win32_Khalesi_RM_MTB{
	meta:
		description = "Trojan:Win32/Khalesi.RM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {99 83 e2 03 03 c2 c1 f8 02 89 45 ?? 8b 4d ?? 81 c1 c6 04 00 00 89 4d ?? 8b 55 ?? 81 3a 72 f3 01 00 75 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}