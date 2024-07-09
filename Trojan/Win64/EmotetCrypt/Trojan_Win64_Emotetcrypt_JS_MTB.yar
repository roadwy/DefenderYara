
rule Trojan_Win64_Emotetcrypt_JS_MTB{
	meta:
		description = "Trojan:Win64/Emotetcrypt.JS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 03 00 00 "
		
	strings :
		$a_03_0 = {48 8b ca 48 2b c8 8b 05 ?? ?? ?? ?? 0f af 05 ?? ?? ?? ?? 48 98 48 2b c8 48 63 05 ?? ?? ?? ?? 48 2b c8 8b 05 ?? ?? ?? ?? 0f af 05 ?? ?? ?? ?? 48 98 48 2b c8 48 8b 44 24 38 0f b6 04 08 44 33 c0 8b 05 ?? ?? ?? ?? 8b 0c 24 03 c8 8b 15 ?? ?? ?? ?? 0f af 15 ?? ?? ?? ?? 8b 05 ?? ?? ?? ?? 03 c1 03 d0 } //1
		$a_01_1 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } //10 DllRegisterServer
		$a_01_2 = {32 70 24 3e 29 5a 5e 49 56 5e 61 6f 41 38 25 30 61 39 35 53 53 6b 4e 40 6d } //1 2p$>)Z^IV^aoA8%0a95SSkN@m
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*10+(#a_01_2  & 1)*1) >=11
 
}