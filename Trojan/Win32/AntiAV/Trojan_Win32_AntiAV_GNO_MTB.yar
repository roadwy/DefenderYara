
rule Trojan_Win32_AntiAV_GNO_MTB{
	meta:
		description = "Trojan:Win32/AntiAV.GNO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b ec 83 ec ?? 80 65 fd 00 56 68 ?? ?? ?? ?? c6 45 f0 53 c6 45 f1 68 c6 45 f2 65 c6 45 f3 6c c6 45 f4 6c c6 45 f5 45 c6 45 f6 78 c6 45 f7 65 c6 45 f8 63 c6 45 f9 75 c6 45 fa 74 c6 45 fb 65 c6 45 fc 41 ff 15 } //10
		$a_01_1 = {c6 45 f8 6b c6 45 f9 69 c6 45 fa 6c c6 45 fb 6c c6 45 fc 68 c6 45 fd 79 } //10
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*10) >=20
 
}