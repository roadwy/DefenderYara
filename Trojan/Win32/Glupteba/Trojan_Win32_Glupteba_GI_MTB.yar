
rule Trojan_Win32_Glupteba_GI_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.GI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {01 df 31 10 47 29 db 81 c0 01 00 00 00 39 c8 75 e3 21 fb } //10
	condition:
		((#a_01_0  & 1)*10) >=10
 
}