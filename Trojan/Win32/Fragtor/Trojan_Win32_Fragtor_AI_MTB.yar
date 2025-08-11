
rule Trojan_Win32_Fragtor_AI_MTB{
	meta:
		description = "Trojan:Win32/Fragtor.AI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {c7 45 fc 04 00 00 00 8d 4d c8 c7 45 e0 00 00 00 00 2b ce c7 45 e4 00 00 00 00 b8 ?? ?? ?? ?? c7 45 e8 00 00 00 00 f7 e9 c1 fa 02 8b c2 c1 e8 1f } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}