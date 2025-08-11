
rule Trojan_Win32_Midie_A_MTB{
	meta:
		description = "Trojan:Win32/Midie.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {50 68 06 00 02 00 6a 00 68 a0 41 00 10 68 01 00 00 80 ff 15 04 30 00 10 85 c0 75 23 51 ?? b9 a1 06 00 00 59 68 05 15 00 00 ff } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}