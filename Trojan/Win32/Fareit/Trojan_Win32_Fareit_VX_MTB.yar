
rule Trojan_Win32_Fareit_VX_MTB{
	meta:
		description = "Trojan:Win32/Fareit.VX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {85 c0 31 f7 66 83 f8 ?? 66 85 d2 85 ff 66 81 fa ?? ?? 89 3c 10 66 85 db 85 ff 81 fb ?? ?? ?? ?? 66 a9 ?? ?? 5f 85 db 85 db 66 a9 ?? ?? 66 3d ?? ?? 83 c2 ?? 66 83 ff ?? 66 81 fb ?? ?? 83 fb ?? 85 d2 83 c7 ?? 85 c0 66 85 db 66 85 d2 81 fa ?? ?? ?? ?? 75 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}