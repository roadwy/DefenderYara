
rule Trojan_Win32_Farfli_MAQ_MTB{
	meta:
		description = "Trojan:Win32/Farfli.MAQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {83 c4 08 8d 45 fc 50 68 3f 00 0f 00 6a 00 8d 8d f8 fe ff ff 51 68 02 00 00 80 ff 15 } //01 00 
		$a_01_1 = {8b 45 08 8a 08 32 4d ec 8b 55 08 88 0a 8b 45 08 8a 08 02 4d ec 8b 55 08 88 0a b8 } //00 00 
	condition:
		any of ($a_*)
 
}