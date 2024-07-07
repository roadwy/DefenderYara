
rule Trojan_Win32_SmokeLoader_EM_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.EM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 01 00 00 "
		
	strings :
		$a_01_0 = {99 b9 12 00 00 00 f7 f9 8b 55 0c 03 55 fc 0f b6 0a 33 c8 8b 55 0c 03 55 fc 88 0a } //6
	condition:
		((#a_01_0  & 1)*6) >=6
 
}