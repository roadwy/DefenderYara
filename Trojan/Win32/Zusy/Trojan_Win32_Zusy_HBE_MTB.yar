
rule Trojan_Win32_Zusy_HBE_MTB{
	meta:
		description = "Trojan:Win32/Zusy.HBE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {e8 05 00 00 00 e9 ?? ?? ?? ?? 83 c0 0f 8b 3c 24 29 c7 01 fb e8 4a 00 00 00 85 c0 75 01 c3 89 c1 51 be ?? ?? ?? ?? 01 fe ff 16 85 c0 75 0b e8 3c 00 00 00 85 c0 75 f7 eb db 89 c1 e8 23 00 00 00 85 c0 74 d0 50 51 be ?? ?? ?? ?? 01 fe ff 16 89 c6 e8 0d 00 00 00 85 c0 75 01 c3 85 f6 74 02 89 30 eb d6 e8 07 00 00 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}