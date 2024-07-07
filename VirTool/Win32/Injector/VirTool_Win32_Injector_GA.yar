
rule VirTool_Win32_Injector_GA{
	meta:
		description = "VirTool:Win32/Injector.GA,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {c6 85 cc fd ff ff 72 c6 85 cd fd ff ff 7a c6 85 ce fd ff ff 7a c7 85 3c ff ff ff d0 01 00 00 c6 85 c3 fd ff ff 7d c7 45 d8 00 00 00 00 c7 45 d8 00 00 00 00 eb 34 c7 85 38 ff ff ff 57 01 00 00 8d 95 c3 fd ff ff 8b 45 d8 01 d0 8a 00 83 f0 16 8d 8d c3 fd ff ff 8b 55 d8 01 ca 88 02 c7 85 34 ff ff ff 12 00 00 00 ff 45 d8 83 7d d8 0b 0f 9e c0 84 c0 75 c1 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}