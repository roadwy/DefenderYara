
rule Trojan_Win32_Emotet_PEJ_MTB{
	meta:
		description = "Trojan:Win32/Emotet.PEJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 03 00 00 "
		
	strings :
		$a_02_0 = {0f b6 b4 04 [0-04] 88 54 0c ?? 8a 54 04 ?? 0f b6 fa 03 f1 03 fe 8b cf 81 e1 ff 00 00 80 88 5c 04 } //1
		$a_02_1 = {0f b6 5c 34 ?? 0f b6 d2 03 da 81 e3 ff 00 00 80 79 ?? 4b 81 cb ?? ?? ?? ?? 43 8a 54 1c ?? 32 14 0f 88 11 } //1
		$a_81_2 = {23 34 4b 50 71 68 31 70 48 4c 62 68 68 4b 4d 50 6d 75 4f 57 31 31 25 47 49 65 24 51 4d 30 31 4a 5a 66 70 55 42 4c 78 78 6d 61 54 46 76 24 4e 6e 44 4d 51 46 70 33 6c 64 4e 56 7d 6b 62 65 78 45 41 50 73 6e 58 58 51 78 34 73 79 75 40 63 7e 24 40 71 78 4c 45 66 54 41 49 3f 74 34 67 25 5a 71 53 41 7a 31 2a 39 73 68 4e 62 51 70 7d 39 3f } //1 #4KPqh1pHLbhhKMPmuOW11%GIe$QM01JZfpUBLxxmaTFv$NnDMQFp3ldNV}kbexEAPsnXXQx4syu@c~$@qxLEfTAI?t4g%ZqSAz1*9shNbQp}9?
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1+(#a_81_2  & 1)*1) >=1
 
}