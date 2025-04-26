
rule Trojan_Win32_GuLoader_RPD_MTB{
	meta:
		description = "Trojan:Win32/GuLoader.RPD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_01_0 = {8f 04 30 d9 f3 de c8 eb 42 0a 45 d7 54 85 85 85 85 85 85 } //1
		$a_01_1 = {84 db 31 1c 08 84 db 83 c1 04 d9 e8 eb 51 be 9d e5 65 56 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=1
 
}