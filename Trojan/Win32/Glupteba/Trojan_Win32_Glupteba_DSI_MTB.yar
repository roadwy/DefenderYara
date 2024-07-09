
rule Trojan_Win32_Glupteba_DSI_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.DSI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {bb 87 d5 7c 3a 81 45 ?? 8c eb 73 22 8b 9d ?? ?? ?? ?? 8b 4d ?? 8b c3 d3 e0 03 85 ?? ?? ?? ?? 89 45 ?? 8b 85 ?? ?? ?? ?? 03 c3 c1 eb 05 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}