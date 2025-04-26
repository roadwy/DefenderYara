
rule Trojan_Win32_REntS_SIBT7_MTB{
	meta:
		description = "Trojan:Win32/REntS.SIBT7!MTB,SIGNATURE_TYPE_PEHSTR_EXT,15 00 0b 00 03 00 00 "
		
	strings :
		$a_03_0 = {88 01 8b 45 ?? 03 45 ?? 0f b6 00 83 c0 ?? 8b 4d 90 1b 00 03 4d 90 1b 01 88 01 } //10
		$a_03_1 = {88 01 8b 45 ?? 03 45 ?? 8a 00 2c ?? 8b 4d 90 1b 00 03 4d 90 1b 01 88 01 } //10
		$a_03_2 = {8a 06 84 c0 90 18 6b ff ?? 0f be c0 03 f8 46 8a 06 84 c0 75 ?? 3b 7d ?? 74 } //1
	condition:
		((#a_03_0  & 1)*10+(#a_03_1  & 1)*10+(#a_03_2  & 1)*1) >=11
 
}