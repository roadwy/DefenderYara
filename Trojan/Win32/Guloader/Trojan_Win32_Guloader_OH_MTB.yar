
rule Trojan_Win32_Guloader_OH_MTB{
	meta:
		description = "Trojan:Win32/Guloader.OH!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {00 66 85 d2 85 ff 85 db 85 c0 5b 66 85 db 85 db 66 81 ff a4 83 85 d2 01 d3 3d 4e 57 1c 2c 85 d2 66 3d 29 bb 09 0b eb 71 } //00 00 
	condition:
		any of ($a_*)
 
}