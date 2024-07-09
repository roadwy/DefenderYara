
rule Trojan_Win32_Insebro_A{
	meta:
		description = "Trojan:Win32/Insebro.A,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {68 24 01 01 00 68 ?? ?? 00 10 8b 44 24 34 68 ?? ?? 00 10 50 ff 15 ?? ?? 00 10 83 f8 06 0f 84 6d 01 00 00 8b 4e 08 6a 00 68 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}