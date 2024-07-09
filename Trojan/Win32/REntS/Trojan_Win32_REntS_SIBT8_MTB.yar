
rule Trojan_Win32_REntS_SIBT8_MTB{
	meta:
		description = "Trojan:Win32/REntS.SIBT8!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {0f b6 02 05 ?? ?? ?? ?? 8b 4d ?? 03 4d ?? 88 01 } //1
		$a_03_1 = {88 0a 8b 55 ?? 03 55 ?? 8a 02 2c 01 8b 4d ?? 03 4d ?? 88 01 } //1
		$a_03_2 = {8a 1a 84 db 74 ?? 8b c8 8d 52 ?? c1 e0 ?? 03 c1 0f be cb 8a 1a 03 c1 84 db 75 ?? 8b 4d 08 3b 45 0c 74 ?? 8b 55 ?? 46 3b f1 72 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}