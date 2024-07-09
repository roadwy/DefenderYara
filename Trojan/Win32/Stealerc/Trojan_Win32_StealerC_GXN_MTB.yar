
rule Trojan_Win32_StealerC_GXN_MTB{
	meta:
		description = "Trojan:Win32/StealerC.GXN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {30 14 30 83 bc 24 ?? ?? ?? ?? 0f ?? ?? 6a 00 6a 00 57 8d 44 24 ?? 50 53 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}