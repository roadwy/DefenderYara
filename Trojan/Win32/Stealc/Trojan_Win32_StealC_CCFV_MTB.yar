
rule Trojan_Win32_StealC_CCFV_MTB{
	meta:
		description = "Trojan:Win32/StealC.CCFV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {83 ff 2d 75 ?? 6a 00 ff 15 ?? ?? ?? ?? e8 ?? ?? ?? ?? 30 04 33 83 ff 0f 75 ?? 6a 00 [0-06] 6a 00 6a 00 6a 00 6a 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}