
rule Trojan_Win32_StealC_GXW_MTB{
	meta:
		description = "Trojan:Win32/StealC.GXW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {30 04 37 83 7d ?? 0f ?? ?? 53 8d 85 ?? ?? ?? ?? 50 53 ff 15 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}