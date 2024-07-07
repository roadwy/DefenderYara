
rule Trojan_Win32_Ekstak_GNB_MTB{
	meta:
		description = "Trojan:Win32/Ekstak.GNB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {72 44 6c 50 74 53 cd e6 d7 7b 0b 2a 01 00 00 00 bd 4a 36 00 5a a9 32 00 00 da 0a 00 73 5b 0d ca bc 6d 32 00 00 d4 00 00 b3 cf 16 16 } //1
		$a_01_1 = {56 00 6f 00 6c 00 75 00 6d 00 65 00 55 00 54 00 49 00 4c 00 20 00 53 00 65 00 74 00 75 00 70 00 } //1 VolumeUTIL Setup
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}