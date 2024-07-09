
rule Trojan_Win32_Emotet_DEU_MTB{
	meta:
		description = "Trojan:Win32/Emotet.DEU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_02_0 = {03 c1 99 b9 4f 11 00 00 f7 f9 8b 85 ?? ?? ?? ?? 8a 8c 15 ?? ?? ?? ?? 30 08 [0-04] ff 8d ?? ?? ?? ?? 89 85 90 1b 00 0f 85 } //1
		$a_81_1 = {63 74 6c 63 79 6f 4b 51 57 61 4a 67 67 61 62 41 65 4b 72 4c 4e 66 74 59 71 52 44 } //1 ctlcyoKQWaJggabAeKrLNftYqRD
	condition:
		((#a_02_0  & 1)*1+(#a_81_1  & 1)*1) >=1
 
}