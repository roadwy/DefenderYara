
rule Trojan_Win32_DanaBot_VQ_MTB{
	meta:
		description = "Trojan:Win32/DanaBot.VQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {8a 00 88 45 ab 8a 45 ab 04 9f 2c 1a 73 04 80 6d ab 20 a1 90 01 04 8a 00 88 45 aa 8a 45 aa 04 9f 2c 1a 73 04 80 6d aa 20 a1 90 01 04 8a 00 88 45 a9 8a 45 a9 04 9f 2c 1a 73 04 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}