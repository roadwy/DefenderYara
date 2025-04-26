
rule Trojan_Win32_Glupteba_EH_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.EH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_01_0 = {21 d0 31 3e 29 d2 21 d0 46 01 c0 48 39 ce } //5
		$a_01_1 = {31 37 21 c2 47 40 39 df 75 e9 } //5
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5) >=5
 
}