
rule Trojan_Win32_MultiPlug_DA_MTB{
	meta:
		description = "Trojan:Win32/MultiPlug.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8a 45 0c 8b 16 02 c3 0f b6 c8 8b 45 08 d3 ca 33 d0 2b d3 89 16 83 c6 04 4b 75 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}