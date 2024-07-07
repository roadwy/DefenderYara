
rule Trojan_Win32_Kryptic_AA_MTB{
	meta:
		description = "Trojan:Win32/Kryptic.AA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b6 04 0f 00 81 90 01 04 0f b6 b1 90 01 04 8a 14 0f 0f b6 04 0e 88 04 0f 88 14 0e 0f b6 81 90 01 04 0f b6 91 90 01 04 0f b6 04 08 02 04 0a 0f b6 c0 0f b6 04 08 30 83 90 01 04 43 81 fb 90 01 04 7c 90 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}