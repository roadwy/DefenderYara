
rule Trojan_Win32_Redline_BU_MTB{
	meta:
		description = "Trojan:Win32/Redline.BU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {2b f0 8b c6 c1 e0 04 03 45 ec c7 05 [0-04] 19 36 6b ff 89 45 fc 8b c6 c1 e8 05 89 45 0c 8d 45 0c 50 e8 [0-04] 8d 04 33 50 8d 45 fc 50 e8 [0-04] 8b 45 fc 33 45 0c 81 c3 47 86 c8 61 2b f8 ff 4d f8 0f } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}