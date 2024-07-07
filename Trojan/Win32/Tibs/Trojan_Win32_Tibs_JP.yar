
rule Trojan_Win32_Tibs_JP{
	meta:
		description = "Trojan:Win32/Tibs.JP,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {74 11 60 83 ec 08 0f 01 0c 24 58 90 09 07 00 83 bd 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}