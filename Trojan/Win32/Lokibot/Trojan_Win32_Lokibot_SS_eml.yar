
rule Trojan_Win32_Lokibot_SS_eml{
	meta:
		description = "Trojan:Win32/Lokibot.SS!eml,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {b8 05 00 00 00 8b 55 08 03 d0 73 05 e8 90 02 04 80 32 4b 40 3d 00 5c 00 00 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}