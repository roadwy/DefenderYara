
rule Trojan_Win32_StealC_GCM_MTB{
	meta:
		description = "Trojan:Win32/StealC.GCM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b6 c0 8a 84 04 ?? ?? ?? ?? 8b 4c 24 ?? 30 04 0e 89 c8 40 39 e8 8b 54 24 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}