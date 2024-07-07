
rule Trojan_Win32_Whispergate_RPX_MTB{
	meta:
		description = "Trojan:Win32/Whispergate.RPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {89 c1 89 d8 ba 00 00 00 00 f7 f1 8b 45 0c 01 d0 0f b6 00 32 45 e7 88 06 83 45 f4 01 8b 45 08 89 04 24 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}