
rule Trojan_Win32_Ekstak_MBXH_MTB{
	meta:
		description = "Trojan:Win32/Ekstak.MBXH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {55 8b ec 6a ff 68 ?? 04 4c 00 68 ?? a0 4b 00 64 a1 00 00 00 00 50 64 89 25 00 00 00 00 83 ec 58 53 56 57 89 65 e8 ff 15 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}