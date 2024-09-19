
rule Trojan_Win32_Ulise_GXU_MTB{
	meta:
		description = "Trojan:Win32/Ulise.GXU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {69 51 c6 44 24 ?? 6d c6 44 24 ?? 6d c6 44 24 ?? 33 c6 44 24 ?? 32 c6 44 24 ?? 2e c6 44 24 ?? 64 c6 44 24 ?? 6c c6 44 24 ?? 6c c6 44 24 ?? 00 ff 15 ?? ?? ?? ?? 8b f0 85 f6 0f 84 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}