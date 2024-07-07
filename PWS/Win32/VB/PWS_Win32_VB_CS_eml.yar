
rule PWS_Win32_VB_CS_eml{
	meta:
		description = "PWS:Win32/VB.CS!eml,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {0f c8 0f c8 89 c0 89 ff 85 c0 89 ff 89 db 89 c0 31 04 1f } //1
		$a_03_1 = {0f c8 0f c8 0f c8 0f c8 89 c0 89 c0 89 ff 0f c8 0f c8 90 0a 40 00 b8 90 01 04 89 90 00 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}