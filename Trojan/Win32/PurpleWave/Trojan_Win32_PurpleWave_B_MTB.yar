
rule Trojan_Win32_PurpleWave_B_MTB{
	meta:
		description = "Trojan:Win32/PurpleWave.B!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8a ca 02 c9 8a c1 0c 01 84 d2 0f b6 c0 89 90 01 02 8b d0 0f b6 c1 0f 49 d0 89 90 01 02 83 eb 01 75 90 02 04 90 02 15 88 04 1a 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}