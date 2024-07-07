
rule Trojan_Win32_Redline_GPAD_MTB{
	meta:
		description = "Trojan:Win32/Redline.GPAD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {e8 ae 3b 00 00 80 b6 90 01 05 e8 62 41 00 00 8b d8 8b 0b 8b 49 04 8b 4c 19 30 8b 79 04 8b cf 90 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}