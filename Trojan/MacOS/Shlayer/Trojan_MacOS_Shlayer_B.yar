
rule Trojan_MacOS_Shlayer_B{
	meta:
		description = "Trojan:MacOS/Shlayer.B,SIGNATURE_TYPE_MACHOHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_01_0 = {44 65 6e 69 73 20 53 61 66 72 6f 6e 6f 76 31 } //1 Denis Safronov1
		$a_00_1 = {42 33 54 4b 47 39 50 4b 46 33 31 } //1 B3TKG9PKF31
		$a_02_2 = {0f b6 0c 01 48 8b 55 ?? 2a 4c 02 ?? 88 4d ff 0f b6 4d ff 48 8b 55 f0 88 4c 15 ea 48 ff 45 ?? 48 8b 4d ?? 48 83 f9 ?? 76 d3 } //2
	condition:
		((#a_01_0  & 1)*1+(#a_00_1  & 1)*1+(#a_02_2  & 1)*2) >=4
 
}