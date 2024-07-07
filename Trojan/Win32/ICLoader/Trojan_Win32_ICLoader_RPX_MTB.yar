
rule Trojan_Win32_ICLoader_RPX_MTB{
	meta:
		description = "Trojan:Win32/ICLoader.RPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {57 33 ff 57 ff d6 83 f8 07 75 1f 6a 01 ff d6 25 00 ff 00 00 3d 00 0d 00 00 74 07 3d 00 04 00 00 75 08 5f b8 01 00 00 00 5e c3 8b c7 5f 5e c3 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_Win32_ICLoader_RPX_MTB_2{
	meta:
		description = "Trojan:Win32/ICLoader.RPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {62 c3 5a 00 ff 21 57 00 00 da 0a 00 73 5b 0d ca ac c1 56 00 00 d4 00 00 29 42 b3 73 } //1
		$a_01_1 = {4d 00 49 00 58 00 41 00 75 00 64 00 69 00 6f 00 } //1 MIXAudio
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
rule Trojan_Win32_ICLoader_RPX_MTB_3{
	meta:
		description = "Trojan:Win32/ICLoader.RPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {88 87 33 00 25 e6 2f 00 00 da 0a 00 73 5b 0d ca 92 aa 2f 00 00 d4 00 00 55 63 05 9b } //1
		$a_01_1 = {51 00 74 00 35 00 4f 00 70 00 65 00 6e 00 47 00 4c 00 } //1 Qt5OpenGL
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
rule Trojan_Win32_ICLoader_RPX_MTB_4{
	meta:
		description = "Trojan:Win32/ICLoader.RPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {9d 7a 74 00 14 df 70 00 00 be 0a 00 0b 33 49 b9 c7 97 70 00 00 dc 01 00 1f d0 c2 43 } //1
		$a_01_1 = {51 00 54 00 52 00 61 00 64 00 69 00 6f 00 42 00 75 00 74 00 74 00 6f 00 6e 00 } //1 QTRadioButton
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
rule Trojan_Win32_ICLoader_RPX_MTB_5{
	meta:
		description = "Trojan:Win32/ICLoader.RPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 03 00 00 "
		
	strings :
		$a_01_0 = {d7 7b 0b 2a 01 00 00 00 99 60 49 00 b5 cb 45 00 00 ae 0a 00 23 97 28 5f 6c 90 45 00 00 d4 00 00 d8 96 a9 71 } //10
		$a_01_1 = {7b 4b 49 00 97 b6 45 00 00 ae 0a 00 23 97 28 5f 3b 7b 45 00 00 d4 00 00 4d c2 0b 88 } //10
		$a_01_2 = {42 00 75 00 73 00 69 00 6e 00 65 00 73 00 73 00 54 00 56 00 } //1 BusinessTV
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*1) >=11
 
}