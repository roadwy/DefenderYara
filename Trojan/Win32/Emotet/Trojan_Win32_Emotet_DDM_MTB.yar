
rule Trojan_Win32_Emotet_DDM_MTB{
	meta:
		description = "Trojan:Win32/Emotet.DDM!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 4c 24 04 8b 54 24 08 56 8b c1 8b f2 0b ca f7 d0 f7 d6 0b c6 5e 23 c1 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}