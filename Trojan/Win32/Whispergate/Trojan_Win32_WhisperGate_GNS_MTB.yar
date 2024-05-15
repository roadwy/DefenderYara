
rule Trojan_Win32_WhisperGate_GNS_MTB{
	meta:
		description = "Trojan:Win32/WhisperGate.GNS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_01_0 = {8b 55 f4 8b 45 08 8d 0c 02 8b 55 f4 8b 45 08 01 d0 0f b6 18 8b 45 f4 99 f7 7d f0 89 d0 89 c2 8b 45 0c 01 d0 0f b6 00 31 d8 88 01 83 45 f4 01 8b 45 f4 3b 45 ec } //00 00 
	condition:
		any of ($a_*)
 
}