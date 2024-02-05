
rule Trojan_Win32_Neoreblamy_AC_MTB{
	meta:
		description = "Trojan:Win32/Neoreblamy.AC!MTB,SIGNATURE_TYPE_PEHSTR,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_01_0 = {8b 45 f4 0f b6 84 05 45 ff ff ff 8b 4d f4 2b 4d d0 0f b6 8c 0d 42 ff ff ff 0f be 8c 0d b8 fe ff ff 0b c1 8b 4d f4 0f b6 8c 0d 45 ff ff ff 8b 55 f4 2b 55 d0 0f b6 94 15 42 ff ff ff 0f be 94 15 b8 fe ff ff 23 ca 2b c1 8b 4d f4 0f b6 8c 0d 44 ff ff ff 88 84 0d b8 fe ff ff 83 65 d0 00 } //00 00 
	condition:
		any of ($a_*)
 
}