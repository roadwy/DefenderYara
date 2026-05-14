
rule Trojan_Win32_Zusy_MKC_MTB{
	meta:
		description = "Trojan:Win32/Zusy.MKC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 02 00 00 "
		
	strings :
		$a_03_0 = {0f b7 44 56 08 66 85 c0 ?? ?? 25 ff 0f 00 00 8b cb 03 06 2b 4c 24 28 01 0c 28 42 3b d7 } //20
		$a_01_1 = {57 69 6e 64 6f 77 73 52 65 73 69 6c 69 65 6e 63 65 53 65 72 76 69 63 65 4d 75 74 65 78 } //15 WindowsResilienceServiceMutex
	condition:
		((#a_03_0  & 1)*20+(#a_01_1  & 1)*15) >=30
 
}