
rule Trojan_Win32_Emotet_PDO_MTB{
	meta:
		description = "Trojan:Win32/Emotet.PDO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 03 00 00 "
		
	strings :
		$a_02_0 = {81 e1 ff 00 00 00 03 c1 b9 ?? ?? ?? ?? 99 f7 f9 8a 03 8a 94 14 ?? ?? ?? ?? 32 c2 88 03 } //1
		$a_02_1 = {0f b6 cb 03 c1 99 b9 ?? ?? ?? ?? f7 f9 8a 5d ?? 8a 94 14 ?? ?? ?? ?? 32 da 88 5d } //1
		$a_81_2 = {6d 38 35 74 36 4c 30 4b 4c 30 38 59 4f 54 4c 34 4c 43 38 70 54 4d 52 45 79 72 43 50 49 4c 54 44 37 57 67 4d 68 6f } //1 m85t6L0KL08YOTL4LC8pTMREyrCPILTD7WgMho
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1+(#a_81_2  & 1)*1) >=1
 
}