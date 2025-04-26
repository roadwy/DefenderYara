
rule Trojan_Win32_Ramnit_C{
	meta:
		description = "Trojan:Win32/Ramnit.C,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b d0 68 02 00 00 00 68 00 30 00 10 52 ff 75 08 e8 ?? ?? ?? ?? 0b c0 75 05 8b 45 08 eb 01 40 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}