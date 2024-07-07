
rule Trojan_Win32_Pterodo_YAE_MTB{
	meta:
		description = "Trojan:Win32/Pterodo.YAE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {83 ea 01 0f b6 0c 11 31 c8 88 c2 8b 86 0c 32 00 00 8b 8e 04 32 00 00 88 14 08 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}