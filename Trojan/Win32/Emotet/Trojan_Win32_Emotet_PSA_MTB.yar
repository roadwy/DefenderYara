
rule Trojan_Win32_Emotet_PSA_MTB{
	meta:
		description = "Trojan:Win32/Emotet.PSA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_02_0 = {0f b6 cb 03 c1 99 b9 ?? ?? ?? ?? f7 f9 8b 44 24 ?? 8b 4c 24 ?? 40 89 44 24 ?? 8a 54 14 ?? 30 54 01 } //1
		$a_81_1 = {7a 59 37 58 54 75 64 52 73 4f 46 4c 48 35 41 48 69 6b 63 4f 62 30 71 56 46 54 59 61 53 6d 6b 79 72 44 73 72 55 } //1 zY7XTudRsOFLH5AHikcOb0qVFTYaSmkyrDsrU
	condition:
		((#a_02_0  & 1)*1+(#a_81_1  & 1)*1) >=1
 
}