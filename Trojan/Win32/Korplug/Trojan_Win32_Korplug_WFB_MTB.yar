
rule Trojan_Win32_Korplug_WFB_MTB{
	meta:
		description = "Trojan:Win32/Korplug.WFB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 45 0c 8a 4d e0 d3 f8 30 44 37 08 83 fb 03 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}