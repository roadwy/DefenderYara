
rule Trojan_Win32_Straba_RB_MTB{
	meta:
		description = "Trojan:Win32/Straba.RB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8a 08 88 8d ?? fe ff ff b8 01 00 00 00 b9 01 00 00 00 8a 95 ?? fe ff ff 0f b6 f2 81 ee b8 00 00 00 89 cf 89 85 ?? fe ff ff 89 8d ?? fe ff ff 89 b5 ?? fe ff ff 89 bd ?? fe ff ff } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}