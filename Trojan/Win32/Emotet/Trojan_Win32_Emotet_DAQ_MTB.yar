
rule Trojan_Win32_Emotet_DAQ_MTB{
	meta:
		description = "Trojan:Win32/Emotet.DAQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {6a 00 6a 00 89 03 ff d6 6a 00 6a 00 ff d6 6a 00 6a 00 ff d6 8b 13 8b 44 24 20 6a 00 6a 00 57 52 6a 01 50 55 ff 15 ?? ?? ?? ?? 5e 5b 85 c0 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}