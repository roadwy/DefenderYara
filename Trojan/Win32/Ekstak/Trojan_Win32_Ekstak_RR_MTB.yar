
rule Trojan_Win32_Ekstak_RR_MTB{
	meta:
		description = "Trojan:Win32/Ekstak.RR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {51 8b 44 24 00 50 ff 15 4c a3 64 00 6a 00 ff 15 8c a0 64 00 6a 00 6a 00 6a 03 6a 00 6a 03 68 00 00 00 40 68 58 e0 64 00 ff 15 48 a3 64 00 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}