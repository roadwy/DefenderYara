
rule Trojan_Win32_Redline_DI_MTB{
	meta:
		description = "Trojan:Win32/Redline.DI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {88 55 db 0f b6 45 db 83 c0 7c 88 45 db 0f b6 4d db c1 f9 03 0f b6 55 db c1 e2 05 0b ca 88 4d db 0f b6 45 db 05 cd 00 00 00 88 45 db 8b 4d dc 8a 55 db 88 54 0d e8 e9 } //00 00 
	condition:
		any of ($a_*)
 
}