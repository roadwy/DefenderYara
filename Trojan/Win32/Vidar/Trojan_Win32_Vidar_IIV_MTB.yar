
rule Trojan_Win32_Vidar_IIV_MTB{
	meta:
		description = "Trojan:Win32/Vidar.IIV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8a 04 37 34 74 04 4e 34 70 2c 65 34 22 2c 73 68 ?? ?? ?? ?? 88 04 37 e8 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}