
rule Backdoor_Win32_Netwire_GG_MTB{
	meta:
		description = "Backdoor:Win32/Netwire.GG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,15 00 14 00 08 00 00 "
		
	strings :
		$a_80_0 = {53 4f 46 54 57 41 52 45 5c 4e 65 74 57 69 72 65 } //SOFTWARE\NetWire  15
		$a_80_1 = {66 69 6c 65 6e 61 6d 65 73 2e 74 78 74 } //filenames.txt  1
		$a_80_2 = {48 6f 73 74 49 64 } //HostId  1
		$a_80_3 = {25 52 61 6e 64 25 } //%Rand%  1
		$a_80_4 = {47 45 54 20 25 73 20 48 54 54 50 2f 31 2e 31 } //GET %s HTTP/1.1  1
		$a_80_5 = {41 63 63 65 70 74 2d 4c 61 6e 67 75 61 67 65 3a 20 65 6e 2d 55 53 2c 65 6e } //Accept-Language: en-US,en  1
		$a_80_6 = {43 6f 6e 6e 65 63 74 69 6f 6e 3a 20 63 6c 6f 73 65 } //Connection: close  1
		$a_80_7 = {32 30 30 20 4f 4b } //200 OK  1
	condition:
		((#a_80_0  & 1)*15+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1+(#a_80_6  & 1)*1+(#a_80_7  & 1)*1) >=20
 
}