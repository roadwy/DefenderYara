
rule Trojan_Win32_Convagent_PA_MTB{
	meta:
		description = "Trojan:Win32/Convagent.PA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {f7 d2 88 95 90 01 04 0f b6 85 90 01 04 83 c0 90 01 01 88 85 90 01 04 0f b6 8d 90 01 04 c1 f9 90 01 01 0f b6 95 90 01 04 c1 e2 90 01 01 0b ca 88 8d 90 01 04 0f b6 85 90 01 04 2b 85 90 01 04 88 85 90 01 04 0f b6 8d 90 01 04 f7 d1 88 8d 90 01 04 0f b6 95 90 01 04 f7 da 88 95 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}