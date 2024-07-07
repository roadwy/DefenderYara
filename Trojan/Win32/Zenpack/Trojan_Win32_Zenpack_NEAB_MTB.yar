
rule Trojan_Win32_Zenpack_NEAB_MTB{
	meta:
		description = "Trojan:Win32/Zenpack.NEAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {75 1c 8b 45 e4 8b 48 02 8b 09 8a 11 80 fa ff 89 ce 89 75 f8 89 4d f4 88 55 f3 74 da eb 0b 8b 45 e4 8a 08 89 45 f4 88 4d f3 8a 45 f3 8b 4d f4 31 d2 88 d4 3c b8 89 4d ec } //10
	condition:
		((#a_01_0  & 1)*10) >=10
 
}