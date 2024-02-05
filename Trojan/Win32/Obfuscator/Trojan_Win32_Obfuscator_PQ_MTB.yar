
rule Trojan_Win32_Obfuscator_PQ_MTB{
	meta:
		description = "Trojan:Win32/Obfuscator.PQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {0f b6 cb 03 c1 8b ce 99 f7 f9 8b 45 14 83 c4 0c 8a 8c 15 90 01 04 30 08 40 ff 4d 08 89 45 14 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}