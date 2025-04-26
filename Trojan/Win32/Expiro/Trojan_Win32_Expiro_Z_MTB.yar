
rule Trojan_Win32_Expiro_Z_MTB{
	meta:
		description = "Trojan:Win32/Expiro.Z!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {2e 72 65 6c 6f 63 00 00 00 [0-15] 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 e2 } //1
		$a_01_1 = {8d 4c 24 04 83 e4 f0 31 c0 ff 71 fc 55 89 e5 57 56 8d 55 a4 53 89 d7 51 b9 11 00 00 00 83 ec 78 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}