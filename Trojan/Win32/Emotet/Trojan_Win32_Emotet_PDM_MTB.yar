
rule Trojan_Win32_Emotet_PDM_MTB{
	meta:
		description = "Trojan:Win32/Emotet.PDM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_02_0 = {0f b6 cb 03 c1 99 b9 ?? ?? ?? ?? f7 f9 8d 4c 24 ?? 83 c5 01 0f b6 94 14 ?? ?? ?? ?? 30 55 } //1
		$a_81_1 = {64 34 35 77 68 30 59 44 38 49 32 49 75 35 67 70 6c 76 6c 4d 65 50 54 54 57 63 34 33 70 4b 61 33 6f 59 4b 65 4a } //1 d45wh0YD8I2Iu5gplvlMePTTWc43pKa3oYKeJ
	condition:
		((#a_02_0  & 1)*1+(#a_81_1  & 1)*1) >=1
 
}