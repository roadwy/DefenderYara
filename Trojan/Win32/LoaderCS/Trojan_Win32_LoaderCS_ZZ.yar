
rule Trojan_Win32_LoaderCS_ZZ{
	meta:
		description = "Trojan:Win32/LoaderCS.ZZ,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {83 c0 40 3d 90 09 0b 00 66 0f f8 c1 0f 11 80 90 09 07 00 0f 11 80 90 09 0b 00 66 0f f8 c1 0f 11 80 90 09 07 00 0f 11 80 90 09 0b 00 66 0f f8 c1 0f 11 80 90 09 07 00 0f 11 80 90 09 0b 00 66 0f f8 c1 0f 11 80 90 09 07 00 0f 11 80 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}