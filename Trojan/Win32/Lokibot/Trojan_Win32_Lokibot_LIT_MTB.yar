
rule Trojan_Win32_Lokibot_LIT_MTB{
	meta:
		description = "Trojan:Win32/Lokibot.LIT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b6 44 16 01 88 85 00 fd ff ff 83 f0 cc 88 44 13 01 8d 42 02 39 f8 73 0c 0f b6 44 16 ?? 83 f0 cc 88 44 13 02 83 bd 04 fd ff ff 0e 0f 86 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}