
rule Trojan_Win32_RedlineStealer_Z_MTB{
	meta:
		description = "Trojan:Win32/RedlineStealer.Z!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_00_0 = {23 00 2b 00 33 00 3b 00 43 00 53 00 63 00 73 00 } //1 #+3;CScs
		$a_00_1 = {68 10 84 2d 2c 71 ea 7e 2c 71 ea 7e 2c 71 ea 7e 32 23 7f 7e 3f 71 ea 7e 0b b7 91 7e 2b 71 ea 7e 2c 71 eb 7e 5c 71 ea 7e 32 23 6e 7e 1c 71 ea 7e 32 23 69 7e a2 71 ea 7e 32 23 7b 7e 2d 71 ea 7e } //1
		$a_00_2 = {83 ec 38 53 b0 d7 88 44 24 2b 88 44 24 2f b0 c1 88 44 24 30 88 44 24 31 88 44 24 33 55 56 8b f1 b8 0c 00 fe ff 2b c6 89 44 24 14 b8 0d 00 fe ff 2b c6 89 44 24 1c b8 02 00 fe ff 2b c6 89 44 24 } //1
		$a_01_3 = {64 65 6c 65 74 65 5b 5d } //1 delete[]
		$a_01_4 = {63 6f 6e 73 74 72 75 63 74 6f 72 20 6f 72 20 66 72 6f 6d 20 44 6c 6c 4d 61 69 6e } //1 constructor or from DllMain
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}