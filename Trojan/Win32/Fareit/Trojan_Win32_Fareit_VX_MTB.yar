
rule Trojan_Win32_Fareit_VX_MTB{
	meta:
		description = "Trojan:Win32/Fareit.VX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {85 c0 31 f7 66 83 f8 90 01 01 66 85 d2 85 ff 66 81 fa 90 01 02 89 3c 10 66 85 db 85 ff 81 fb 90 01 04 66 a9 90 01 02 5f 85 db 85 db 66 a9 90 01 02 66 3d 90 01 02 83 c2 90 01 01 66 83 ff 90 01 01 66 81 fb 90 01 02 83 fb 90 01 01 85 d2 83 c7 90 01 01 85 c0 66 85 db 66 85 d2 81 fa 90 01 04 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}