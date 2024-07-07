
rule Trojan_Win32_Razy_AZY_MTB{
	meta:
		description = "Trojan:Win32/Razy.AZY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {12 1f 33 99 90 01 04 f8 cf 2b f4 8b 4b 6c 89 ec 06 d3 cd a7 8d 76 f7 03 6a 95 61 5b 18 5b 18 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}