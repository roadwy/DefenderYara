
rule Trojan_Win32_Glupteba_DSJ_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.DSJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_03_0 = {bb 87 d5 7c 3a 81 45 90 01 01 8c eb 73 22 8b 45 90 01 01 8b 4d 90 01 01 8b d0 d3 e2 03 f8 c1 90 00 } //1
		$a_03_1 = {e8 05 03 85 90 01 01 fd ff ff 03 95 90 01 01 fd ff ff 89 bd 90 01 01 fd ff ff 89 55 90 01 01 89 45 90 01 01 8b 85 90 01 01 fd ff ff 31 45 90 01 01 81 3d 90 01 04 3f 0b 00 00 75 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=1
 
}