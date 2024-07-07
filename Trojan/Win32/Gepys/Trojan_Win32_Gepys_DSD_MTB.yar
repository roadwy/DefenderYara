
rule Trojan_Win32_Gepys_DSD_MTB{
	meta:
		description = "Trojan:Win32/Gepys.DSD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {88 df 8a 08 fe cf 20 f9 8a 3a 00 df 08 d9 88 38 88 0a } //1
		$a_02_1 = {8b 55 e0 01 c2 8b 45 e4 d3 e0 8b 5d fc 03 45 e0 ff 45 f4 e8 90 01 04 81 7d f4 e8 07 00 00 7d 90 00 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}