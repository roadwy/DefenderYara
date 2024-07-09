
rule Trojan_Win32_Tibs_JD{
	meta:
		description = "Trojan:Win32/Tibs.JD,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8d 55 f4 52 51 6a 04 57 ff 55 fc 90 09 14 00 0f 6f ?? 89 c1 0f 7e ?? fc b9 ?? ?? ?? ?? 81 f1 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}