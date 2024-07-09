
rule Trojan_Win32_Kibik_B{
	meta:
		description = "Trojan:Win32/Kibik.B,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {eb e5 89 45 fc ff 75 fc e8 ?? ?? 00 00 03 45 fc 96 83 ee 34 4e 8a 06 3c 3e 75 05 e9 ?? 01 00 00 46 89 75 ec } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}