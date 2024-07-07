
rule Trojan_Win32_Emotet_DV{
	meta:
		description = "Trojan:Win32/Emotet.DV,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {68 4a 72 6a 33 32 68 57 } //1 hJrj32hW
	condition:
		((#a_01_0  & 1)*1) >=1
 
}