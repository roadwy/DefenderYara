
rule Trojan_Win32_Lokibot_SK_eml{
	meta:
		description = "Trojan:Win32/Lokibot.SK!eml,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_03_0 = {33 c0 8b d3 03 d0 73 05 e8 90 01 04 80 32 3b 40 3d 7a 5b 00 00 90 00 } //1
		$a_03_1 = {33 c0 8b d3 03 d0 73 05 e8 90 01 04 80 32 12 40 3d 48 5c 00 00 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=1
 
}