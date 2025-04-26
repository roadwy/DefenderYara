
rule Trojan_Win32_StealC_JGM_MTB{
	meta:
		description = "Trojan:Win32/StealC.JGM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b d3 c1 ea 05 89 55 fc 8b 45 e8 01 45 fc 8b c3 c1 e0 04 03 45 e4 8d 0c 1f 33 c1 33 45 fc 89 45 ec } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}