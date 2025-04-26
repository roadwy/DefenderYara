
rule Trojan_Win32_Copak_AMAX_MTB{
	meta:
		description = "Trojan:Win32/Copak.AMAX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {1e b2 47 00 [0-0f] 12 b4 47 00 [0-28] 81 ?? ff 00 00 00 [0-14] 31 [0-37] 81 ?? 34 b4 47 00 0f 8c ?? ff ff ff } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}