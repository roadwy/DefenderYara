
rule Trojan_Win32_Bussdo_A{
	meta:
		description = "Trojan:Win32/Bussdo.A,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {72 e2 eb 0a 8b 84 bd ?? ?? ff ff 89 45 fc 8d 85 c8 fe ff ff 50 ff 15 ?? ?? 40 00 83 f8 ff 6a 0a 6a 65 0f 85 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}