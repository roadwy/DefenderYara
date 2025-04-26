
rule Trojan_Win32_Wireload_A_dha{
	meta:
		description = "Trojan:Win32/Wireload.A!dha,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 89 5c 24 10 48 89 74 24 18 55 57 41 56 48 8d 6c 24 80 48 81 ec 80 01 00 00 e8 ?? ?? ?? ?? ba fc 25 72 3b 48 8b c8 48 8b f8 e8 ?? ?? ?? ?? ba 8a f8 c4 02 48 89 44 24 38 48 8b cf e8 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}