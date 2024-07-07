
rule Trojan_Win32_Guloader_OM_MTB{
	meta:
		description = "Trojan:Win32/Guloader.OM!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {66 81 fa 3e 29 85 db 01 d3 66 85 db 85 ff 31 0b 81 fb 9d e0 fc 81 66 85 c0 83 c2 04 85 db e9 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}