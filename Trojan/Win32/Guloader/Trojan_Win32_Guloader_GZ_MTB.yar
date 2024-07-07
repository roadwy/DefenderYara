
rule Trojan_Win32_Guloader_GZ_MTB{
	meta:
		description = "Trojan:Win32/Guloader.GZ!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {66 85 c0 66 85 db 5b 85 d2 66 81 ff f7 94 01 d3 85 db 81 fa e6 c1 f5 a6 31 0b 85 db e9 b2 00 00 00 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}