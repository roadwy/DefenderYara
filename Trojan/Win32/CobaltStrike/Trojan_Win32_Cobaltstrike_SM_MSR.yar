
rule Trojan_Win32_Cobaltstrike_SM_MSR{
	meta:
		description = "Trojan:Win32/Cobaltstrike.SM!MSR,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {66 0f ef c2 0f 11 80 ?? ?? ?? ?? 0f 10 80 ?? ?? ?? ?? 66 0f ef c8 0f 11 88 ?? ?? ?? ?? 83 c0 40 3d 40 03 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}