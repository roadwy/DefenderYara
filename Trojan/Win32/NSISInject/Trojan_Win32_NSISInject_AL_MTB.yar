
rule Trojan_Win32_NSISInject_AL_MTB{
	meta:
		description = "Trojan:Win32/NSISInject.AL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {6a 00 68 80 00 00 00 6a 03 6a 00 6a 01 68 00 00 00 80 8b 4d 0c 8b 51 04 52 ff 15 90 02 04 89 45 ec 6a 00 8b 45 ec 50 ff 15 90 02 04 89 45 f8 6a 40 68 00 30 00 00 8b 4d f8 51 6a 00 ff 15 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}