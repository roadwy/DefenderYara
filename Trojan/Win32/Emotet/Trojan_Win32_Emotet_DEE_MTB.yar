
rule Trojan_Win32_Emotet_DEE_MTB{
	meta:
		description = "Trojan:Win32/Emotet.DEE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_02_0 = {03 c2 99 b9 ?? ?? ?? ?? f7 f9 8b 4c 24 ?? 8b 84 24 ?? ?? ?? ?? 8a 1c 01 8a 54 14 ?? 32 da 88 1c 01 [0-04] 89 4c 24 ?? 8b 8c 24 ?? ?? ?? ?? 85 c9 0f 85 } //1
		$a_81_1 = {6d 36 73 43 65 45 6d 4f 57 6c 33 36 31 66 77 39 51 58 44 50 74 65 56 31 5a 35 6a 77 31 39 57 6f 6a 62 } //1 m6sCeEmOWl361fw9QXDPteV1Z5jw19Wojb
	condition:
		((#a_02_0  & 1)*1+(#a_81_1  & 1)*1) >=1
 
}