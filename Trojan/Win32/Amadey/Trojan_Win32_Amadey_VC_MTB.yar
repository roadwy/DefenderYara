
rule Trojan_Win32_Amadey_VC_MTB{
	meta:
		description = "Trojan:Win32/Amadey.VC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b6 84 34 ?? ?? ?? ?? 0f b6 cb 03 c1 99 b9 ?? ?? ?? ?? f7 f9 8d 4c 24 ?? 45 0f b6 94 14 ?? ?? ?? ?? 30 55 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}