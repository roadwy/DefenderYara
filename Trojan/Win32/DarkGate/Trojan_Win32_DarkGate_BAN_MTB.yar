
rule Trojan_Win32_DarkGate_BAN_MTB{
	meta:
		description = "Trojan:Win32/DarkGate.BAN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {33 d2 f7 75 fc 43 8a 04 32 8b 55 f8 32 04 0a 8b 55 f4 88 01 3b 5d 08 72 d8 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}