
rule Trojan_Win32_Emotet_DF{
	meta:
		description = "Trojan:Win32/Emotet.DF,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {58 79 49 52 42 74 64 46 6c 4d 73 49 } //1 XyIRBtdFlMsI
	condition:
		((#a_01_0  & 1)*1) >=1
 
}