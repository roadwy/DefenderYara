
rule Backdoor_Win32_Caphaw_C{
	meta:
		description = "Backdoor:Win32/Caphaw.C,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {8a 11 8a c2 32 45 08 83 7d 0c 01 88 01 75 04 84 c0 eb 08 83 7d 0c 00 75 04 84 d2 74 1b 8b 45 08 69 c0 4d 03 00 00 05 41 02 00 00 33 d2 83 ce ff f7 f6 41 89 55 08 eb c8 } //1
		$a_01_1 = {2e 63 63 2f 70 69 6e 67 2e 68 74 6d 6c } //1 .cc/ping.html
		$a_01_2 = {42 6f 74 6e 65 74 3d } //1 Botnet=
		$a_01_3 = {48 4a 56 65 72 3d 31 2e 33 } //1 HJVer=1.3
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}