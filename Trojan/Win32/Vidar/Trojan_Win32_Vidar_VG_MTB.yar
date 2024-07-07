
rule Trojan_Win32_Vidar_VG_MTB{
	meta:
		description = "Trojan:Win32/Vidar.VG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8a 00 32 c1 8b 8d 80 e4 ff ff 88 04 11 ff 85 84 e4 ff ff ff b5 7c e4 ff ff 42 89 95 78 e4 ff ff e8 90 01 04 59 39 85 84 e4 ff ff 0f 8c 56 ff ff ff 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}