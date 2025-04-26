
rule Trojan_Win32_Netwire_B_MTB{
	meta:
		description = "Trojan:Win32/Netwire.B!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 55 08 8b 45 fc 2b 42 0c 6b c8 0c 51 8b 55 08 6b 42 0c 0c 8b 4d 08 03 01 50 8b 55 08 8b 42 0c 83 c0 40 6b c8 0c 8b 55 08 03 0a 51 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}