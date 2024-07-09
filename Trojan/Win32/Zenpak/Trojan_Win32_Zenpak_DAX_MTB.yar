
rule Trojan_Win32_Zenpak_DAX_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.DAX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 4d d4 8a 0c 0b 8b 5d e0 32 0c 33 8b 75 e4 8b 5d d4 88 0c 1e c7 05 [0-04] 33 00 00 00 8b 4d f0 39 cf 8b 4d d0 89 55 ec 89 4d dc 89 7d d8 0f } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}