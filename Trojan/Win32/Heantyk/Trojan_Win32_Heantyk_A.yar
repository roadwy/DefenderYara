
rule Trojan_Win32_Heantyk_A{
	meta:
		description = "Trojan:Win32/Heantyk.A,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8d 45 fc ff 75 f8 50 e8 ?? ?? 00 00 eb 87 50 e8 ?? ?? 00 00 c7 04 24 ?? ?? 40 00 ff 75 f4 8d 45 f8 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}