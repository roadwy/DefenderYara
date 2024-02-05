
rule Trojan_Win32_VBInject_BA_MTB{
	meta:
		description = "Trojan:Win32/VBInject.BA!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {c1 f9 1f 8b d1 33 c8 33 d7 3b ca 7f 1f 8b 4d 0c 8b 09 8b 51 0c 8b 79 14 2b d7 8a cb 8d 3c 02 8a 14 02 33 ca 33 c8 03 c6 88 0f eb } //00 00 
	condition:
		any of ($a_*)
 
}