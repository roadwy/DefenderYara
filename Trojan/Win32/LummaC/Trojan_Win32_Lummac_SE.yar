
rule Trojan_Win32_Lummac_SE{
	meta:
		description = "Trojan:Win32/Lummac.SE,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 44 24 08 8b 54 24 04 89 54 24 fc 89 74 24 f8 89 7c 24 f4 8b 4c 24 0c 8d 74 24 10 8d 7c 24 04 f3 a4 8b 74 24 f8 8b 7c 24 f4 8d 54 24 04 ff 54 24 fc c3 } //10
	condition:
		((#a_01_0  & 1)*10) >=10
 
}