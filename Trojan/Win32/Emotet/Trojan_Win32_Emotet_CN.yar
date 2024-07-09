
rule Trojan_Win32_Emotet_CN{
	meta:
		description = "Trojan:Win32/Emotet.CN,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_02_0 = {68 57 52 4a 52 45 47 52 45 4a 45 47 23 90 04 0a 0b 23 24 45 65 47 48 68 6a 6e 52 00 00 } //1
		$a_02_1 = {68 57 52 4a 52 45 47 52 45 4a 45 47 23 90 09 1d 00 00 90 04 0a 0b 23 24 45 65 47 48 68 6a 6e 52 00 00 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=1
 
}