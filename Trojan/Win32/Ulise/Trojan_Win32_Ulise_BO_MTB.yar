
rule Trojan_Win32_Ulise_BO_MTB{
	meta:
		description = "Trojan:Win32/Ulise.BO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 45 08 8d 4e 01 8a 04 06 88 04 1a 8b c2 33 d2 8b 75 14 f7 75 10 ff 45 fc 03 f1 85 d2 8b 55 fc 0f 45 f1 3b 55 0c 72 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}