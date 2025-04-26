
rule Trojan_Win32_Glupteba_GV_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.GV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {42 e8 11 00 00 00 4a 31 33 09 c9 43 89 d1 21 ca 39 fb 75 e7 09 c9 c3 } //10
	condition:
		((#a_01_0  & 1)*10) >=10
 
}