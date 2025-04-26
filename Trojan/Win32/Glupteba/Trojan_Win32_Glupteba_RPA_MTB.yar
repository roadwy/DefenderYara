
rule Trojan_Win32_Glupteba_RPA_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.RPA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {21 db 29 df 31 16 47 81 eb ?? ?? ?? ?? 46 47 39 ce 75 df } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Glupteba_RPA_MTB_2{
	meta:
		description = "Trojan:Win32/Glupteba.RPA!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {31 3b 21 d0 81 c3 04 00 00 00 39 f3 75 f2 81 c1 ac 53 a9 f7 81 e9 01 00 00 00 c3 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}