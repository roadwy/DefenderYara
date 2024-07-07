
rule Trojan_Win32_Glupteba_FK_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.FK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {81 c3 01 00 00 00 b8 d8 85 40 00 4f 29 df e8 10 00 00 00 31 01 81 c1 01 00 00 00 21 db 39 d1 75 e5 4b c3 } //10
	condition:
		((#a_01_0  & 1)*10) >=10
 
}