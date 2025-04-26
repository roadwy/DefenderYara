
rule TrojanDropper_Win32_Tracur_gen_J{
	meta:
		description = "TrojanDropper:Win32/Tracur.gen!J,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_03_0 = {55 89 e5 59 e8 00 00 00 00 5a 55 89 e5 68 ?? ?? ?? ?? 5a 57 b8 67 10 00 00 68 af 04 00 00 59 83 ed 08 03 45 10 e8 01 00 00 00 c3 66 29 10 83 c0 02 5f 57 47 49 74 02 } //1
		$a_03_1 = {e8 02 00 00 00 eb 10 85 c0 74 02 31 c0 c3 66 29 10 83 c0 02 e2 f8 c3 55 89 e5 68 ?? ?? ?? ?? 5a 57 b8 ?? 10 00 00 68 ?? ?? 00 00 59 83 ed 04 03 45 0c e8 d7 ff ff ff } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=1
 
}