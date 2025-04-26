
rule Trojan_Win32_Netwire_MBHH_MTB{
	meta:
		description = "Trojan:Win32/Netwire.MBHH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {03 e8 03 00 00 07 ac 0a 00 00 08 b4 04 00 00 ff 03 32 00 00 00 0c 08 } //1
		$a_01_1 = {7c 18 40 00 fe f9 f7 01 20 ff ff ff 08 } //1
		$a_01_2 = {e9 00 00 00 d4 29 40 00 c0 16 40 00 e8 13 40 00 78 00 00 00 82 00 00 00 8c } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}