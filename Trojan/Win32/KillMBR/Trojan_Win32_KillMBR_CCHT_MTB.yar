
rule Trojan_Win32_KillMBR_CCHT_MTB{
	meta:
		description = "Trojan:Win32/KillMBR.CCHT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {6a 00 6a 00 6a 03 6a 00 6a 03 68 00 00 00 10 68 ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b f0 6a 00 8d 45 fc 50 68 00 28 00 00 68 ?? ?? ?? ?? 56 e8 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}