
rule TrojanSpy_Win32_Hitpop_AJ{
	meta:
		description = "TrojanSpy:Win32/Hitpop.AJ,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_03_0 = {7e 55 bf 01 00 00 00 ff 45 f4 83 7d f4 10 7e 07 c7 45 f4 01 00 00 00 8d 45 e0 8b 55 ec 8b 4d f4 8a 54 0a ff e8 ?? ?? fe ff 8b 45 e0 e8 ?? ?? ff ff 8b 55 f0 0f b6 54 3a ff 33 c2 89 45 f8 } //2
		$a_01_1 = {eb 9a 46 83 c3 24 83 fe 15 0f 85 3d ff ff ff } //1
		$a_01_2 = {2f 61 63 74 69 76 65 2e 61 73 70 3f 74 67 69 64 3d 6d 79 73 65 6c 66 } //2 /active.asp?tgid=myself
		$a_01_3 = {2f 63 63 2e 74 78 74 20 48 54 54 50 2f 31 2e 31 } //1 /cc.txt HTTP/1.1
		$a_01_4 = {43 3a 5c 57 49 4e 44 4f 57 53 5c 63 63 2e 65 78 65 } //1 C:\WINDOWS\cc.exe
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*2+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}