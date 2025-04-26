
rule Trojan_Win32_Maui_RPJ_MTB{
	meta:
		description = "Trojan:Win32/Maui.RPJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8a 4d 10 33 45 10 d3 ff 03 7d 08 03 45 08 ff 4d f0 8a 0f 88 4d df 8a 08 88 0f 8a 4d df } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}