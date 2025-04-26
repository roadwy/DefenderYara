
rule Trojan_Win32_Emotet_PG_bit{
	meta:
		description = "Trojan:Win32/Emotet.PG!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {5b 53 83 c3 3c ff 33 5b f7 db 29 1c 24 5b 8d 9b b4 00 00 00 83 eb 10 } //1
		$a_03_1 = {41 c7 41 01 6a 68 72 6b 51 8d 05 ?? ?? ?? ?? ff 10 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}