
rule Trojan_Win32_Ekstak_MBYH_MTB{
	meta:
		description = "Trojan:Win32/Ekstak.MBYH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {55 8b ec 6a ff 68 a0 96 64 00 68 00 83 64 00 64 a1 00 00 00 00 50 64 89 25 00 00 00 00 83 ec 68 53 56 57 89 65 e8 33 db } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}