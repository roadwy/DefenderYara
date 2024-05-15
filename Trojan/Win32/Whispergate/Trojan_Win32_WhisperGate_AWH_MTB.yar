
rule Trojan_Win32_WhisperGate_AWH_MTB{
	meta:
		description = "Trojan:Win32/WhisperGate.AWH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {01 d0 0f b6 00 0f be c0 83 e8 30 83 f8 09 77 28 8d 54 24 18 8b 44 24 38 01 d0 0f b6 00 0f be c0 83 e8 30 89 44 24 34 8b 44 24 34 89 04 24 } //01 00 
		$a_01_1 = {99 f7 7c 24 30 89 44 24 3c 90 8b 44 24 3c 89 04 24 e8 c3 fe ff ff 83 44 24 38 01 8d 54 24 18 8b 44 24 38 01 d0 0f b6 00 84 c0 } //00 00 
	condition:
		any of ($a_*)
 
}