
rule Trojan_Win32_Rhadamanthys_MOC_MTB{
	meta:
		description = "Trojan:Win32/Rhadamanthys.MOC!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b c6 33 d2 f7 75 10 8a 82 00 90 49 00 32 04 0e 0f b6 1c 0e 8d 0c 18 8b 45 08 88 0c 06 fe c9 88 0c 06 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}