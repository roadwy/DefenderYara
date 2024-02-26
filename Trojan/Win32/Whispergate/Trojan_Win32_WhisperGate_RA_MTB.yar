
rule Trojan_Win32_WhisperGate_RA_MTB{
	meta:
		description = "Trojan:Win32/WhisperGate.RA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 03 00 00 0a 00 "
		
	strings :
		$a_01_0 = {89 c1 89 d8 ba 00 00 00 00 f7 f1 8b 45 0c 01 d0 0f b6 00 32 45 e7 88 06 } //01 00 
		$a_01_1 = {74 65 6d 70 6b 65 79 } //01 00  tempkey
		$a_01_2 = {53 68 65 6c 6c 63 6f 64 65 20 65 78 65 63 75 74 65 64 20 73 75 63 63 65 73 73 66 75 6c 6c 79 } //00 00  Shellcode executed successfully
	condition:
		any of ($a_*)
 
}