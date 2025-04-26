
rule Trojan_Win64_Emotet_BA_MTB{
	meta:
		description = "Trojan:Win64/Emotet.BA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_03_0 = {8b cb 48 8d 7f ?? f7 eb [0-04] ff c3 8b c2 c1 e8 ?? 03 d0 6b c2 ?? 2b c8 48 8b 05 ?? ?? ?? ?? 48 63 d1 0f b6 0c 02 32 4c 3e ?? 88 4f ?? 49 ff cf 75 } //1
		$a_03_1 = {f7 ef c1 fa ?? 83 c7 ?? 8b c2 c1 e8 ?? 03 d0 48 8b 05 ?? ?? ?? ?? 48 63 d2 48 6b d2 ?? 48 03 d0 41 8a 04 10 41 32 04 34 88 06 } //1
		$a_01_2 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } //1 DllRegisterServer
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=2
 
}