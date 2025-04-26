
rule Trojan_MacOS_Lamzev_A_MTB{
	meta:
		description = "Trojan:MacOS/Lamzev.A!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,03 00 03 00 05 00 00 "
		
	strings :
		$a_00_0 = {54 72 6f 6a 61 6e 20 70 61 72 61 6d 65 74 65 72 73 3a } //1 Trojan parameters:
		$a_80_1 = {48 41 43 4b 49 4e 47 20 4d 4f 44 45 3a } //HACKING MODE:  1
		$a_00_2 = {42 69 6e 64 20 73 68 65 6c 6c 20 73 65 72 76 69 63 65 20 6e 61 6d 65 3a } //1 Bind shell service name:
		$a_00_3 = {66 69 6c 65 20 62 75 66 66 65 72 20 74 6f 20 73 6d 61 6c 6c 2e 2e 20 68 6f 77 20 66 75 63 6b 69 6e 67 20 62 69 67 20 69 7a 20 75 72 20 49 6e 66 6f 2e 70 6c 69 73 74 3f 3f } //1 file buffer to small.. how fucking big iz ur Info.plist??
		$a_80_4 = {4c 4f 4c 20 49 20 48 4f 50 45 20 55 20 42 41 43 4b 45 44 20 55 50 20 55 52 20 45 58 45 2e 20 55 20 4d 41 59 20 46 49 4e 44 20 49 54 20 49 5a 2e 2e 20 42 4f 4e 45 52 45 44 } //LOL I HOPE U BACKED UP UR EXE. U MAY FIND IT IZ.. BONERED  1
	condition:
		((#a_00_0  & 1)*1+(#a_80_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_80_4  & 1)*1) >=3
 
}