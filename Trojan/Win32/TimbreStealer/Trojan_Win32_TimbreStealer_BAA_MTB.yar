
rule Trojan_Win32_TimbreStealer_BAA_MTB{
	meta:
		description = "Trojan:Win32/TimbreStealer.BAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b6 ca 0f b6 04 28 03 c7 03 c8 0f b6 f9 8a 44 3c 18 88 44 34 18 46 88 54 3c 18 81 fe ?? ?? ?? ?? 72 d4 } //4
	condition:
		((#a_03_0  & 1)*4) >=4
 
}