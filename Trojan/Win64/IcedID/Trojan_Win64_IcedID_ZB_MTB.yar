
rule Trojan_Win64_IcedID_ZB_MTB{
	meta:
		description = "Trojan:Win64/IcedID.ZB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {f7 e9 d1 fa 8b c2 c1 e8 ?? 03 d0 8d 04 92 3b c8 74 05 01 7d ?? eb ?? ff 4d ?? 8b 4d ?? 41 ?? ?? f7 e9 8b c2 c1 e8 ?? 03 d0 8d 04 52 3b c8 74 } //1
		$a_00_1 = {44 6c 6c 4d 61 69 6e } //1 DllMain
	condition:
		((#a_03_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}
rule Trojan_Win64_IcedID_ZB_MTB_2{
	meta:
		description = "Trojan:Win64/IcedID.ZB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {63 61 73 74 66 64 61 73 75 64 68 79 75 67 61 77 75 6a 64 62 79 61 75 } //1 castfdasudhyugawujdbyau
		$a_01_1 = {73 65 6e 64 42 65 61 63 6f 6e 26 26 49 62 2e 73 65 6e 64 42 65 61 63 6f 6e } //1 sendBeacon&&Ib.sendBeacon
		$a_01_2 = {69 66 28 30 3d 3d 3d 61 2e 69 6e 64 65 78 4f 66 28 22 68 74 74 70 73 3a 2f 2f 22 29 29 72 65 74 75 72 6e 20 32 3b 69 66 28 30 3d 3d 3d 61 2e 69 6e 64 65 78 4f 66 28 22 68 74 74 70 3a 2f 2f 22 29 29 72 65 74 75 72 6e 20 33 7d 72 65 74 75 72 6e 20 31 } //1 if(0===a.indexOf("https://"))return 2;if(0===a.indexOf("http://"))return 3}return 1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}