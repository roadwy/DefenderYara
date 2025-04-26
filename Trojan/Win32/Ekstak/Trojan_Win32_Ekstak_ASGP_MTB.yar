
rule Trojan_Win32_Ekstak_ASGP_MTB{
	meta:
		description = "Trojan:Win32/Ekstak.ASGP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {5f 5e 59 c3 68 ?? ?? ?? 00 6a 01 6a 00 ff 15 ?? ?? ?? 00 85 c0 74 e5 6a 00 ff 15 ?? ?? ?? 00 8b 74 24 08 6a 5a 56 ff 15 ?? ?? ?? 00 56 6a 00 8b f8 ff 15 } //4
		$a_01_1 = {53 74 61 72 73 41 75 64 69 6f 43 6f 6e 76 65 72 74 65 72 } //1 StarsAudioConverter
	condition:
		((#a_03_0  & 1)*4+(#a_01_1  & 1)*1) >=5
 
}