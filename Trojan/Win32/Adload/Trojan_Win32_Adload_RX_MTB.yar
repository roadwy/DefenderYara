
rule Trojan_Win32_Adload_RX_MTB{
	meta:
		description = "Trojan:Win32/Adload.RX!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {89 45 dc 8b 45 e8 0f b6 4c 05 e4 8b 55 dc 0f b6 84 15 c8 fe ff ff 33 c8 8b 55 e8 88 4c 15 e4 e9 3d ff ff ff } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}