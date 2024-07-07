
rule Trojan_Win32_Puzlice_B{
	meta:
		description = "Trojan:Win32/Puzlice.B,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {1b 85 00 1b 86 00 2a 23 78 ff 1b 87 00 2a 23 74 ff 1b 88 00 2a fd b7 36 00 32 04 00 78 ff 74 ff } //1
		$a_01_1 = {50 00 75 00 62 00 6c 00 69 00 63 00 65 00 72 00 3d 00 } //1 Publicer=
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}