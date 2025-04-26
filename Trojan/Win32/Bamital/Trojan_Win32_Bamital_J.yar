
rule Trojan_Win32_Bamital_J{
	meta:
		description = "Trojan:Win32/Bamital.J,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {83 7d 0c 01 75 1d 60 8d 15 ?? ?? ?? ?? 52 e8 90 17 05 01 01 01 01 01 03 0e 61 69 6b ff ff ff 8b c8 0b c9 74 09 8b d0 b8 03 00 00 00 ff d2 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}