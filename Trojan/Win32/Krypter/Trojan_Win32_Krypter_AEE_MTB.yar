
rule Trojan_Win32_Krypter_AEE_MTB{
	meta:
		description = "Trojan:Win32/Krypter.AEE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,16 00 16 00 04 00 00 "
		
	strings :
		$a_03_0 = {55 8b ec 83 ec 08 c6 05 90 01 05 c6 05 90 01 05 c6 05 90 01 05 c6 05 90 01 05 90 02 30 68 90 01 04 ff 15 90 01 04 a3 90 01 04 c7 45 90 01 01 40 00 00 00 c6 05 90 01 04 72 c6 05 90 01 04 7f c6 05 90 01 04 65 c6 05 90 01 05 c6 05 90 01 05 c6 05 90 01 05 c6 05 90 01 05 90 02 30 0f be 05 90 01 04 83 e8 1e a2 90 01 04 0f be 0d 90 01 04 83 e9 14 88 0d 90 01 04 0f be 15 90 01 04 83 ea 14 90 02 36 c6 05 90 01 04 69 68 90 00 } //10
		$a_01_1 = {4c 6f 63 61 6c 41 6c 6c 6f 63 } //2 LocalAlloc
		$a_01_2 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 } //10 VirtualProtect
		$a_01_3 = {47 6c 6f 62 61 6c 41 6c 6c 6f 63 } //2 GlobalAlloc
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*2+(#a_01_2  & 1)*10+(#a_01_3  & 1)*2) >=22
 
}