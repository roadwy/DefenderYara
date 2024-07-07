
rule Trojan_Win32_Zenpak_DE_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.DE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b6 0c 31 8b 75 90 01 01 01 f1 81 e1 90 02 04 8b 75 90 01 01 8b 5d 90 01 01 8a 1c 1e 8b 75 90 01 01 32 1c 0e 8b 4d 90 01 01 8b 75 90 01 01 88 1c 31 8b 4d 90 01 01 39 cf 8b 4d 90 01 01 89 55 90 01 01 89 4d 90 01 01 89 7d 90 01 01 0f 84 90 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}