
rule Trojan_Win32_Emotet_PVZ_MTB{
	meta:
		description = "Trojan:Win32/Emotet.PVZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_02_0 = {f7 f9 8b 4c 24 ?? 8b 84 24 ?? ?? ?? ?? 8a 1c 01 8a 54 14 ?? 32 da 88 1c 01 90 09 05 00 b9 } //1
		$a_81_1 = {45 45 74 65 4d 76 4b 66 57 6e 4b 64 75 4a 68 4d 6e 31 34 42 6f 77 36 68 50 42 5a 79 6f 4d } //1 EEteMvKfWnKduJhMn14Bow6hPBZyoM
	condition:
		((#a_02_0  & 1)*1+(#a_81_1  & 1)*1) >=1
 
}