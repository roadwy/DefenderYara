
rule Trojan_Win32_Glupteba_FU_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.FU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {68 dd 57 41 ac 5a 21 c0 31 39 21 c0 41 39 f1 75 de 50 8b 14 24 83 c4 04 4a c3 } //10
	condition:
		((#a_01_0  & 1)*10) >=10
 
}