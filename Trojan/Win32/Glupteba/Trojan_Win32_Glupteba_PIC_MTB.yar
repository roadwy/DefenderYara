
rule Trojan_Win32_Glupteba_PIC_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.PIC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {01 44 24 20 8b 4c 24 1c 8b 54 24 14 d3 ea 8b 4c 24 40 8d 44 24 28 c7 05 90 01 04 89 54 24 28 e8 90 01 04 8b 44 24 20 31 44 24 10 81 3d 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}