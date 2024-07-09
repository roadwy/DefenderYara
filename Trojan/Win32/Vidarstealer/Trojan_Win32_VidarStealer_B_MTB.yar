
rule Trojan_Win32_VidarStealer_B_MTB{
	meta:
		description = "Trojan:Win32/VidarStealer.B!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {30 04 33 46 3b f7 } //2
		$a_03_1 = {8a 04 0a 8b 15 ?? ?? ?? ?? 88 04 0a 41 3b 0d } //2
	condition:
		((#a_01_0  & 1)*2+(#a_03_1  & 1)*2) >=4
 
}