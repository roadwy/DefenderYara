
rule Trojan_Win32_Glupteba_ASB_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.ASB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {01 45 fc 8b 55 f8 8b 4d f4 8b c2 d3 e8 03 fa 03 45 d4 33 c7 31 45 fc ff 75 fc 8b c3 } //1
		$a_01_1 = {81 00 47 86 c8 61 c3 81 00 e1 34 ef c6 c3 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}