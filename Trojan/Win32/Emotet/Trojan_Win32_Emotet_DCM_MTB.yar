
rule Trojan_Win32_Emotet_DCM_MTB{
	meta:
		description = "Trojan:Win32/Emotet.DCM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {0f b6 c0 03 c1 b9 ?? ?? ?? ?? 99 f7 f9 8b 44 24 ?? 8a 4c 14 ?? 30 08 [0-03] ff 4c 24 ?? 89 44 24 ?? 0f 85 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}