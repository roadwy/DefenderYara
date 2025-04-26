
rule Trojan_Win32_Guloader_OW_MTB{
	meta:
		description = "Trojan:Win32/Guloader.OW!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {00 00 5b 81 fa e2 30 ef 66 85 d2 66 85 d2 3d e9 c0 ec d5 01 d3 85 c0 85 c0 85 db 66 85 c0 09 0b 81 ff e7 67 09 58 85 d2 66 85 db eb 17 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}