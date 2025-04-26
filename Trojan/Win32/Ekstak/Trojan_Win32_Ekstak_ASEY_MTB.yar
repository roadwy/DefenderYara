
rule Trojan_Win32_Ekstak_ASEY_MTB{
	meta:
		description = "Trojan:Win32/Ekstak.ASEY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_03_0 = {55 8b ec 56 68 34 10 65 00 e8 ?? ?? ?? ff 83 c4 04 a3 } //5
		$a_03_1 = {e5 64 00 50 ff 15 ?? e5 64 00 f7 d8 1b c0 f7 d8 c3 } //5
		$a_03_2 = {50 ff d6 68 ?? ?? ?? 00 50 ff d7 8b 0d ?? ?? ?? 00 a3 ?? ?? ?? 00 51 ff d6 68 ?? ?? ?? 00 50 ff d7 5f } //5
	condition:
		((#a_03_0  & 1)*5+(#a_03_1  & 1)*5+(#a_03_2  & 1)*5) >=5
 
}