
rule Trojan_Win32_IceID_AD_MTB{
	meta:
		description = "Trojan:Win32/IceID.AD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {8b c8 2b ce 83 c1 04 0f b7 c9 89 4c 24 90 01 01 8d 8d 90 01 04 66 01 0d 90 01 04 8b 0a 81 fe 90 01 04 75 90 00 } //1
		$a_02_1 = {8b d8 6b c0 90 01 01 2b de 83 c3 90 01 01 81 c1 90 01 04 0f b7 db 89 0a 0f b7 2d 90 01 04 89 0d 90 01 04 0f b7 cb 2b c1 8d 98 90 01 04 0f b7 05 90 01 04 03 c5 3d 90 01 04 75 90 00 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}