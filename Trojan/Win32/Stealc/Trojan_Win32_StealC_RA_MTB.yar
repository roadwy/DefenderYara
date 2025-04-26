
rule Trojan_Win32_StealC_RA_MTB{
	meta:
		description = "Trojan:Win32/StealC.RA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 45 f8 83 c0 64 89 45 fc 83 6d fc 64 8b 45 08 8a 4d fc 03 c2 30 08 42 3b d7 7c } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}