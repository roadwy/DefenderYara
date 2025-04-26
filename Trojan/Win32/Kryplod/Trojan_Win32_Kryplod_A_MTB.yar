
rule Trojan_Win32_Kryplod_A_MTB{
	meta:
		description = "Trojan:Win32/Kryplod.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_02_0 = {53 68 65 6c c7 45 ?? 6c 45 78 65 c7 45 ?? 63 75 74 65 c7 45 ?? 45 78 57 00 c7 45 ?? 53 48 45 4c c7 45 ?? 4c 33 32 00 ff 15 } //1
		$a_00_1 = {2b c7 d1 f8 8d 34 46 8d 76 02 8d 3c 1e 8b cf 8d 41 02 89 85 9c fd ff ff } //1
		$a_00_2 = {2b f9 be 00 00 00 00 d1 ff b9 fe ff ff ff 8d 04 3f 2b c8 01 8d a8 fd ff ff } //1
	condition:
		((#a_02_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}