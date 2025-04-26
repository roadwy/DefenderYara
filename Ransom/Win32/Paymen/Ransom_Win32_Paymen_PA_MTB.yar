
rule Ransom_Win32_Paymen_PA_MTB{
	meta:
		description = "Ransom:Win32/Paymen.PA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_02_0 = {8b 45 f8 83 c0 01 89 45 f8 83 7d f8 ?? 0f ?? ?? ?? ?? ?? 8b 4d f8 8a 54 [0-04] 88 55 ff 0f b6 45 ff 03 45 f8 88 45 ff 0f b6 4d ff 33 4d f8 88 4d ff 0f b6 55 ff 03 55 f8 88 55 ff 0f b6 45 ff 35 a7 00 00 00 88 45 ff 0f b6 4d ff 81 c1 e3 00 00 00 88 4d ff } //1
		$a_02_1 = {88 45 ff 0f b6 4d ff 03 4d f8 88 4d ff 0f b6 55 ff 33 55 f8 88 55 ff 0f b6 45 ff 05 ec 00 00 00 88 45 ff 0f b6 4d ff 33 4d f8 88 4d ff 0f b6 55 ff 03 55 f8 88 55 ff 8b 45 f8 8a 4d ff 88 4c ?? ?? e9 } //1
		$a_01_2 = {44 00 65 00 61 00 72 00 20 00 75 00 73 00 65 00 72 00 21 00 20 00 59 00 6f 00 75 00 72 00 20 00 63 00 6f 00 6d 00 70 00 75 00 74 00 65 00 72 00 20 00 69 00 73 00 20 00 65 00 6e 00 63 00 72 00 79 00 70 00 74 00 65 00 64 00 21 00 } //1 Dear user! Your computer is encrypted!
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}