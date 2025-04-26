
rule Trojan_Win32_KeyLogger_BH_MTB{
	meta:
		description = "Trojan:Win32/KeyLogger.BH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {06 00 5d fb 33 1c 56 08 00 22 f5 01 00 00 00 6c 00 fe 9e 05 06 00 24 07 00 0f 28 03 19 7c fe 08 7c fe 0d a4 00 2f 00 1a 7c fe 00 02 00 0b 04 ec fd fe 7e } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}