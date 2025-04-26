
rule Trojan_Win32_Bamital_M{
	meta:
		description = "Trojan:Win32/Bamital.M,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {83 7d 0c 01 75 1b 60 68 ?? ?? ?? ?? e8 58 ff ff ff 8b c8 0b c9 74 09 8b d0 b8 03 00 00 00 ff d2 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}