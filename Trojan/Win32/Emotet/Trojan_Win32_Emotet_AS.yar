
rule Trojan_Win32_Emotet_AS{
	meta:
		description = "Trojan:Win32/Emotet.AS,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {33 4d 73 69 44 61 74 61 57 2e 70 64 62 } //1 3MsiDataW.pdb
	condition:
		((#a_01_0  & 1)*1) >=1
 
}