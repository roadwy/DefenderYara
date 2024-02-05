
rule Trojan_Win32_GuLoader_SIBD_MTB{
	meta:
		description = "Trojan:Win32/GuLoader.SIBD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {ff d3 3d e5 90 02 10 be 90 01 04 90 02 10 b9 90 01 04 90 02 10 bf 90 01 04 90 02 10 31 d2 90 02 10 33 14 0e 90 02 10 09 14 08 90 02 10 31 3c 08 90 02 10 81 e9 90 01 04 90 02 10 81 c1 90 01 04 90 02 10 41 7d 90 01 01 90 02 10 ff e0 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}