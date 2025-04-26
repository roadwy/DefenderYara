
rule VirTool_Win32_CryptInject_YD_MTB{
	meta:
		description = "VirTool:Win32/CryptInject.YD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b 45 08 8b 00 8b 4d f8 03 c1 8a 08 88 4d ff 8a 48 01 88 4d fe 8a 48 02 8a 40 03 88 4d fd 8d 4d fd 8d 75 fe 8d 7d ff e8 4e ff ff ff 8b 45 f4 8a 4d ff 83 45 f8 04 88 0c 03 8a 4d fe 43 88 0c 03 8a 4d fd 43 88 0c 03 8b 45 0c 8b 4d f8 43 3b 08 72 ae } //1
		$a_01_1 = {8a d0 80 e2 f0 c0 e2 02 08 17 8a d0 80 e2 fc c0 e2 04 08 16 c0 e0 06 08 01 c3 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}