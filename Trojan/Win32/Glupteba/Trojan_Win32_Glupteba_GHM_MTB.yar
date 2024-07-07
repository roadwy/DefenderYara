
rule Trojan_Win32_Glupteba_GHM_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.GHM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {89 ff 89 d7 bb 90 01 04 09 d7 89 d7 e8 90 01 04 31 1e 46 39 c6 75 90 01 01 c3 09 d7 47 8d 1c 0b 90 00 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}