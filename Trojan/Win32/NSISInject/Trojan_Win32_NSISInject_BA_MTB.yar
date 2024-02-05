
rule Trojan_Win32_NSISInject_BA_MTB{
	meta:
		description = "Trojan:Win32/NSISInject.BA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_03_0 = {83 c4 0c 6a 40 68 00 30 00 00 53 57 ff 15 90 02 04 56 6a 01 8b f8 53 57 e8 90 02 04 83 c4 10 33 c9 85 db 74 16 8b c1 6a 0c 99 5e f7 fe 8a 82 90 02 04 30 04 0f 41 3b cb 72 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}