
rule Trojan_Win32_WhisperGate_A_MTB{
	meta:
		description = "Trojan:Win32/WhisperGate.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 04 00 00 02 00 "
		
	strings :
		$a_01_0 = {40 00 8d 85 f4 fb ff ff 89 04 24 } //02 00 
		$a_01_1 = {89 45 f4 eb } //02 00 
		$a_03_2 = {8b 45 f4 89 44 24 08 c7 44 24 04 00 04 00 00 8d 85 f4 f7 ff ff 89 04 24 e8 90 01 02 00 00 85 c0 75 90 00 } //02 00 
		$a_03_3 = {8d 85 f4 f7 ff ff 89 44 24 04 8d 85 90 01 01 b0 ff ff 89 04 24 e8 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}