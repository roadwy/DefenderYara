
rule Trojan_Win32_Madokwa_CCIB_MTB{
	meta:
		description = "Trojan:Win32/Madokwa.CCIB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b ce 2b c8 03 cb 0f b6 44 0c ?? 8b ce 32 85 ?? ?? ?? ?? 88 47 ?? b8 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}