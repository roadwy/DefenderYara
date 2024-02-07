
rule Trojan_Win32_Koobface_gen_C{
	meta:
		description = "Trojan:Win32/Koobface.gen!C,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 02 00 "
		
	strings :
		$a_03_0 = {6a 7c ff 75 f8 ff 90 01 01 59 3b c3 59 90 00 } //02 00 
		$a_03_1 = {6a 02 ff d7 53 a3 90 01 04 ff 75 fc 68 90 01 04 ff 75 fc ff d6 50 6a 07 90 00 } //01 00 
		$a_01_2 = {2f 63 61 70 2f 3f 61 3d 67 65 74 } //01 00  /cap/?a=get
		$a_01_3 = {63 61 70 74 63 68 61 2e 64 6c 6c 00 63 61 70 74 63 68 61 00 6b 62 64 } //00 00 
	condition:
		any of ($a_*)
 
}