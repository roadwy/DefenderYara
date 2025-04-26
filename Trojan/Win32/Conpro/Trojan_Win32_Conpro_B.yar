
rule Trojan_Win32_Conpro_B{
	meta:
		description = "Trojan:Win32/Conpro.B,SIGNATURE_TYPE_PEHSTR_EXT,07 00 05 00 07 00 00 "
		
	strings :
		$a_03_0 = {83 c0 9f 83 f8 17 0f 87 ?? ?? 00 00 33 c9 8a 88 ?? ?? ?? ?? ff 24 8d ?? ?? ?? ?? 8b 74 24 ?? 83 c9 ff 8b fe 33 c0 f2 ae } //4
		$a_00_1 = {61 73 3a 70 3a 65 3a 6d 3a 78 3a 75 3a } //1 as:p:e:m:x:u:
		$a_00_2 = {43 4f 4e 4e 45 43 54 20 25 73 3a 25 64 20 48 54 54 50 2f 31 2e 30 } //1 CONNECT %s:%d HTTP/1.0
		$a_00_3 = {41 50 4f 43 41 4c 49 50 54 4f 5f 54 48 45 00 } //1
		$a_00_4 = {72 63 66 2e 74 78 74 00 } //1
		$a_00_5 = {74 75 6e 6e 65 6c 20 74 65 73 74 20 6f 6b 21 21 21 } //1 tunnel test ok!!!
		$a_00_6 = {6e 6f 20 63 72 65 61 74 65 20 75 64 70 20 73 6f 63 6b 65 74 21 } //1 no create udp socket!
	condition:
		((#a_03_0  & 1)*4+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1) >=5
 
}