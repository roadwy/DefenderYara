
rule Trojan_Win32_Dridex_SD_MTB{
	meta:
		description = "Trojan:Win32/Dridex.SD!MTB,SIGNATURE_TYPE_PEHSTR,14 00 14 00 02 00 00 0a 00 "
		
	strings :
		$a_01_0 = {8d 50 03 03 d3 8a c2 2a c1 b1 47 2a 44 24 07 f6 e9 2a c2 02 44 24 0c 0f b6 d0 } //0a 00 
		$a_01_1 = {81 c1 e0 d0 ff ff 53 8b 5c 24 08 03 cb 8b c1 80 c1 57 2b c2 02 cb 56 57 } //00 00 
	condition:
		any of ($a_*)
 
}