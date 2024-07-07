
rule Trojan_Win32_Vidar_RE_MTB{
	meta:
		description = "Trojan:Win32/Vidar.RE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 4d fc 8b 15 90 01 04 80 34 11 90 01 01 8d 04 11 8d 45 fc 50 ff 15 90 01 04 8b 4d fc 3b 0d 90 01 04 72 db 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}