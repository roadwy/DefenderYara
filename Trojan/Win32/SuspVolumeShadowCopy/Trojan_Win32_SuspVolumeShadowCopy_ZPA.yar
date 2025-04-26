
rule Trojan_Win32_SuspVolumeShadowCopy_ZPA{
	meta:
		description = "Trojan:Win32/SuspVolumeShadowCopy.ZPA,SIGNATURE_TYPE_CMDHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {76 00 73 00 73 00 61 00 64 00 6d 00 69 00 6e 00 } //1 vssadmin
		$a_00_1 = {63 00 72 00 65 00 61 00 74 00 65 00 20 00 73 00 68 00 61 00 64 00 6f 00 77 00 20 00 2f 00 66 00 6f 00 72 00 3d 00 } //1 create shadow /for=
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}