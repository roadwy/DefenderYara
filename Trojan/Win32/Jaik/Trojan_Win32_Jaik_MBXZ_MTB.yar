
rule Trojan_Win32_Jaik_MBXZ_MTB{
	meta:
		description = "Trojan:Win32/Jaik.MBXZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b ec 6a ff 68 ?? e6 62 00 68 ?? 8a 62 00 64 a1 00 00 00 00 50 64 89 25 00 00 00 00 83 ec 58 53 56 57 89 65 e8 ff 15 ?? e1 62 00 33 d2 8a } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}