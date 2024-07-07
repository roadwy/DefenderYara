
rule Trojan_Win32_Glupteba_H_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.H!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b 34 24 83 c4 04 e8 90 01 04 31 01 29 db 41 43 39 d1 75 e0 90 00 } //10
	condition:
		((#a_02_0  & 1)*10) >=10
 
}