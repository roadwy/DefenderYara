
rule Trojan_Win32_Glupteba_YAG_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.YAG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b d7 d3 ea 03 c7 03 55 e0 33 d0 31 55 f8 8b 45 f8 29 45 ec ff 4d e4 0f 85 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}