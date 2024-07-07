
rule Trojan_Win32_Clipbanker_SPN_MTB{
	meta:
		description = "Trojan:Win32/Clipbanker.SPN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 01 00 00 "
		
	strings :
		$a_03_0 = {0b 07 2c 4f 07 73 0c 00 00 0a 0c 03 18 73 0d 00 00 0a 0d 09 73 0e 00 00 0a 13 04 07 6f 90 01 03 0a d4 8d 0f 00 00 01 13 05 07 11 05 16 11 05 8e 69 6f 90 01 03 0a 26 11 04 11 05 6f 90 01 03 0a 08 6f 90 01 03 0a 11 04 6f 90 01 03 0a 07 6f 90 01 03 0a 2a 90 00 } //3
	condition:
		((#a_03_0  & 1)*3) >=3
 
}