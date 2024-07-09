
rule Trojan_Win32_Glupteba_RPH_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.RPH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {31 13 81 c3 04 00 00 00 39 cb 75 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Glupteba_RPH_MTB_2{
	meta:
		description = "Trojan:Win32/Glupteba.RPH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {31 3e 46 40 39 de 75 [0-10] 29 d0 8d 3c 39 01 c0 21 d0 8b 3f 01 c0 81 e7 ff 00 00 00 41 81 f9 f4 01 00 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}