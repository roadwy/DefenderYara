
rule Trojan_Win32_Gozi_MG_MTB{
	meta:
		description = "Trojan:Win32/Gozi.MG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f af fe 0f b7 71 14 03 f1 8b ce 8b f0 03 cf 81 f6 90 01 04 8b f8 03 f1 89 55 f0 81 f7 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}