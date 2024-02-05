
rule Trojan_Win32_PikaBot_SB_MTB{
	meta:
		description = "Trojan:Win32/PikaBot.SB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {8a 84 0d 6c ff ff ff 32 c2 88 44 0d 90 01 01 41 83 f9 90 01 01 7c 90 00 } //01 00 
		$a_03_1 = {8a 1c 08 8d 43 90 01 01 0f b6 c8 8d 53 90 01 01 80 fa 90 01 01 0f b6 c3 0f 47 c8 8b 45 90 01 01 6b f6 90 01 01 0f be c9 03 f1 8b 4d 90 01 01 40 89 45 90 01 01 3b c7 72 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}