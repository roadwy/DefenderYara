
rule PWS_Win32_Frethog_AE{
	meta:
		description = "PWS:Win32/Frethog.AE,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {ff ff 83 c4 04 85 c0 74 15 6a 01 e8 ?? ?? 00 00 83 c4 04 68 98 3a 00 00 ff 15 ?? ?? 40 00 6a 00 6a 00 6a 00 68 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}