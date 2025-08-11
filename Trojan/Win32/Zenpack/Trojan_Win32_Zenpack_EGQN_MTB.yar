
rule Trojan_Win32_Zenpack_EGQN_MTB{
	meta:
		description = "Trojan:Win32/Zenpack.EGQN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {0f b6 4c 24 15 8b 44 24 18 0f b6 54 24 16 88 0c 03 0f b6 4c 24 17 43 88 14 03 8b 54 24 20 43 88 0c 03 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}