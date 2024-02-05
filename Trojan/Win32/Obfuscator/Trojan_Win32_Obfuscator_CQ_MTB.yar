
rule Trojan_Win32_Obfuscator_CQ_MTB{
	meta:
		description = "Trojan:Win32/Obfuscator.CQ!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b 45 fc 99 f7 bd 7c ff ff ff 89 95 70 ff ff ff 8b 45 ec 03 45 fc 0f be 00 8b 8d 70 ff ff ff 0f be 4c 0d 88 33 c1 8b 4d ec 03 4d fc 88 01 eb } //00 00 
	condition:
		any of ($a_*)
 
}