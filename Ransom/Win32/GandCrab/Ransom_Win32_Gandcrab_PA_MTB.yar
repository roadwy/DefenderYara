
rule Ransom_Win32_Gandcrab_PA_MTB{
	meta:
		description = "Ransom:Win32/Gandcrab.PA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_02_0 = {53 56 57 68 04 01 00 00 bf ?? ?? ?? 00 33 db 57 53 88 1d ?? ?? ?? 00 ff 15 ?? ?? ?? 00 8b 35 ?? ?? ?? 00 89 3d ?? ?? ?? 00 85 f6 74 04 38 1e 75 02 8b f7 8d 45 ?? 50 8d 45 ?? 50 53 53 56 e8 } //1
		$a_02_1 = {50 6a 40 68 00 30 01 00 68 ?? ?? ?? 00 ff 15 ?? ?? ?? 00 85 c0 74 30 ff d7 85 c0 74 13 8d 4d ?? 51 6a 06 53 ff d0 f7 d8 1b c0 23 45 ?? 89 45 ?? 8d 45 ?? 50 ff 75 ?? 68 00 30 01 00 68 ?? ?? ?? 00 ff 15 ?? ?? ?? 00 c7 45 ?? fe ff ff ff 8b 45 ?? eb } //1
		$a_00_2 = {52 65 66 6c 65 63 74 69 76 65 4c 6f 61 64 65 72 } //1 ReflectiveLoader
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}