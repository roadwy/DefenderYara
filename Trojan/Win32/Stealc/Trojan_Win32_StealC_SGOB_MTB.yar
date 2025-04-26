
rule Trojan_Win32_StealC_SGOB_MTB{
	meta:
		description = "Trojan:Win32/StealC.SGOB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_03_0 = {59 8b 4c 24 ?? 0f b6 44 14 ?? 03 c6 0f b6 c0 8a 44 04 ?? 30 04 39 47 3b 3b 7c } //4
	condition:
		((#a_03_0  & 1)*4) >=4
 
}