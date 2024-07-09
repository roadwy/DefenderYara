
rule Trojan_Win32_Emotet_KSP_MTB{
	meta:
		description = "Trojan:Win32/Emotet.KSP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_02_0 = {0f be 04 02 8a d0 0a d8 8b 44 24 ?? f6 d1 f6 d2 0a ca 22 cb 88 08 } //2
		$a_02_1 = {0f be 04 32 8b 4c 24 20 50 51 e8 ?? ?? ?? ?? 88 06 83 c6 01 83 c4 08 83 6c 24 10 01 89 74 24 34 0f 85 } //2
		$a_02_2 = {8b 54 24 24 0f be 04 16 50 55 e8 ?? ?? ?? ?? 88 04 1e 83 c6 01 83 c4 08 3b 74 24 2c 0f 82 } //2
	condition:
		((#a_02_0  & 1)*2+(#a_02_1  & 1)*2+(#a_02_2  & 1)*2) >=2
 
}