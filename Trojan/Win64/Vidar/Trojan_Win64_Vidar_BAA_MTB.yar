
rule Trojan_Win64_Vidar_BAA_MTB{
	meta:
		description = "Trojan:Win64/Vidar.BAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_01_0 = {4c 8b 95 58 02 00 00 47 8a 14 02 41 80 f2 ab 47 88 14 08 84 d2 0f 84 fc 00 00 00 } //2
		$a_01_1 = {5c 4e 65 74 77 6f 72 6b 5c 43 6f 6f 6b 69 65 73 } //1 \Network\Cookies
		$a_01_2 = {5f 6b 65 79 2e 74 78 74 48 } //1 _key.txtH
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=4
 
}