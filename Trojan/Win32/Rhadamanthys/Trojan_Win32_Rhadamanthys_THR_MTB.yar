
rule Trojan_Win32_Rhadamanthys_THR_MTB{
	meta:
		description = "Trojan:Win32/Rhadamanthys.THR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8a 1c 03 32 18 83 c0 04 88 5c 28 fc 8b 5c 24 14 8a 1c 0b 32 58 fd 83 c1 04 88 59 fc 8a 58 fe 32 5e ff 83 c6 04 88 59 fd 8a 58 ff 32 5e fc 88 59 fe ff 4c 24 90 01 01 75 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}