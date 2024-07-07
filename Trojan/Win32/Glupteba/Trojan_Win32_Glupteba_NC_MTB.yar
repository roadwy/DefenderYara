
rule Trojan_Win32_Glupteba_NC_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.NC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {83 c6 08 4f 75 f4 5f 5e c3 90 09 09 00 57 8b f8 56 e8 90 00 } //1
		$a_02_1 = {83 f8 5e 75 07 90 01 01 ff 15 90 01 05 81 90 01 05 7c e4 e8 90 01 04 6a 7b 5e 90 09 07 00 a1 90 01 04 03 90 00 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}