
rule Trojan_Win32_FlyStudio_AFL_MTB{
	meta:
		description = "Trojan:Win32/FlyStudio.AFL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {6a 00 6a 00 6a 00 ff 15 38 65 48 00 8b 4c 24 04 6a 01 6a 00 6a 00 51 68 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_Win32_FlyStudio_AFL_MTB_2{
	meta:
		description = "Trojan:Win32/FlyStudio.AFL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {56 ff d3 8b f0 3b f7 74 3f 6a 02 56 e8 6b fe ff ff 85 c0 74 33 85 ff 74 1f 6a f0 57 ff 15 48 85 4f 00 a9 00 00 00 40 74 0f 57 ff d3 8b f8 ff 15 } //2
		$a_01_1 = {8b f0 85 f6 74 45 56 ff 15 34 86 4f 00 66 3d ff ff 74 2f 6a f0 56 ff 15 48 85 4f 00 a9 00 00 00 10 74 1f 8d 45 f0 50 56 ff 15 80 85 4f 00 ff 75 10 8d 45 f0 ff 75 0c 50 } //1
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}