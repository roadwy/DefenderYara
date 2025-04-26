
rule PUA_Win32_InstallCore_K_{
	meta:
		description = "PUA:Win32/InstallCore.K!!InstallCore.K,SIGNATURE_TYPE_ARHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {31 c0 40 0f a2 3d fb 06 00 00 74 11 3d a1 06 02 00 75 1a 81 fa fd fb 8b 17 74 28 eb 10 81 fa ff fb 8b 0f 74 1e 81 fa ff fb 8b 1f 74 16 c1 e9 1f } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}