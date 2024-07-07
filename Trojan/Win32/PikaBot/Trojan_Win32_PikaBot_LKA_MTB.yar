
rule Trojan_Win32_PikaBot_LKA_MTB{
	meta:
		description = "Trojan:Win32/PikaBot.LKA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8a 04 33 30 06 46 83 ef 01 75 eb } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}