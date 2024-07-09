
rule Trojan_Win32_Glupteba_BX_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.BX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b 04 24 83 c4 04 e8 ?? ?? ?? ?? 09 d8 4b 31 16 48 43 46 21 d8 89 c3 39 ce 75 db } //10
	condition:
		((#a_02_0  & 1)*10) >=10
 
}