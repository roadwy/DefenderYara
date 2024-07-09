
rule Trojan_Win32_Injector_ZD_bit{
	meta:
		description = "Trojan:Win32/Injector.ZD!bit,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {a0 34 30 40 00 ?? d8 88 45 ff 89 5d f8 db 45 f8 dc 1d e8 20 40 00 df e0 9e 76 15 dd 05 e0 20 40 00 90 90 51 8d 85 ?? ?? ff ff dd 1c 24 ff d0 59 59 8a 83 20 30 40 00 8d 8c 1d ?? ?? ff ff 32 45 ff 3c 3a 89 01 77 04 fe c8 88 01 43 eb bd } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}