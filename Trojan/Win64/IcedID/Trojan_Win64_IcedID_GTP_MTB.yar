
rule Trojan_Win64_IcedID_GTP_MTB{
	meta:
		description = "Trojan:Win64/IcedID.GTP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 04 00 00 "
		
	strings :
		$a_01_0 = {44 8b 03 41 8b ff 4d 03 c1 48 8d 5b 04 eb 24 8d 46 20 40 80 fe 61 0f b6 c8 40 0f b6 c6 0f 4d c8 69 ff 01 01 00 00 0f be c1 03 f8 c1 e0 10 33 f8 49 ff c0 41 8a 30 40 84 f6 75 d4 41 3b fe 74 0d ff c2 41 3b 53 18 72 b8 } //10
		$a_01_1 = {6c 6f 61 64 65 72 5f 64 6c 6c 5f 36 34 2e 64 6c 6c } //1 loader_dll_64.dll
		$a_01_2 = {50 6c 75 67 69 6e 49 6e 69 74 } //1 PluginInit
		$a_01_3 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } //1 DllRegisterServer
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=13
 
}