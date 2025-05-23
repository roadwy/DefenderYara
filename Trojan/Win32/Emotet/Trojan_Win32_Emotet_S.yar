
rule Trojan_Win32_Emotet_S{
	meta:
		description = "Trojan:Win32/Emotet.S,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 05 00 00 "
		
	strings :
		$a_00_0 = {c7 02 2e 00 44 00 33 c0 c7 42 04 4c 00 4c 00 } //5
		$a_00_1 = {c7 45 b4 41 00 44 00 c7 45 b8 4d 00 49 00 c7 45 bc 4e 00 24 00 } //5
		$a_00_2 = {c7 85 68 ff ff ff 25 00 53 00 c7 85 6c ff ff ff 79 00 73 00 c7 85 70 ff ff ff 74 00 65 00 c7 85 74 ff ff ff 6d 00 52 00 c7 85 78 ff ff ff 6f 00 6f 00 c7 85 7c ff ff ff 74 00 25 00 } //5
		$a_03_3 = {63 00 72 00 [0-02] c7 ?? ?? 79 00 70 00 c7 ?? ?? 74 00 33 00 c7 ?? ?? 32 00 2e 00 c7 ?? ?? 64 00 6c 00 } //5
		$a_03_4 = {6e 00 65 00 [0-04] c7 45 e0 74 00 61 00 c7 45 e4 70 00 69 00 c7 45 e8 33 00 32 00 c7 45 ec 2e 00 64 00 c7 45 f0 6c 00 6c 00 } //5
	condition:
		((#a_00_0  & 1)*5+(#a_00_1  & 1)*5+(#a_00_2  & 1)*5+(#a_03_3  & 1)*5+(#a_03_4  & 1)*5) >=20
 
}