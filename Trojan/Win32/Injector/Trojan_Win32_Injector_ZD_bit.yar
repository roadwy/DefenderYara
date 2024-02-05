
rule Trojan_Win32_Injector_ZD_bit{
	meta:
		description = "Trojan:Win32/Injector.ZD!bit,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {a0 34 30 40 00 90 01 01 d8 88 45 ff 89 5d f8 db 45 f8 dc 1d e8 20 40 00 df e0 9e 76 15 dd 05 e0 20 40 00 90 90 51 8d 85 90 01 02 ff ff dd 1c 24 ff d0 59 59 8a 83 20 30 40 00 8d 8c 1d 90 01 02 ff ff 32 45 ff 3c 3a 89 01 77 04 fe c8 88 01 43 eb bd 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}