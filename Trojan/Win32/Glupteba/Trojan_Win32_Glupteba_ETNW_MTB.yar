
rule Trojan_Win32_Glupteba_ETNW_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.ETNW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b 4c 24 1c d3 e8 30 04 3e 81 fd 49 06 00 00 0f 85 ?? ?? ?? ?? 89 54 24 18 } //2
	condition:
		((#a_02_0  & 1)*2) >=2
 
}