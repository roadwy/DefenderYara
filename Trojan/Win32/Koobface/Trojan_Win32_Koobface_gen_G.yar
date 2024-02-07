
rule Trojan_Win32_Koobface_gen_G{
	meta:
		description = "Trojan:Win32/Koobface.gen!G,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 06 00 00 02 00 "
		
	strings :
		$a_03_0 = {eb 1c 6a 7c 50 c6 45 90 01 01 01 ff 15 90 01 04 59 3b c3 59 74 09 40 50 90 00 } //02 00 
		$a_01_1 = {42 83 c1 04 83 fa 03 72 eb 85 c0 74 07 03 04 b5 } //01 00 
		$a_01_2 = {2f 63 61 70 2f 3f 61 3d 71 75 65 72 79 } //01 00  /cap/?a=query
		$a_01_3 = {2f 63 61 70 2f 3f 61 3d 73 61 76 65 } //01 00  /cap/?a=save
		$a_01_4 = {2f 67 6f 6f 2f 3f 61 3d 25 73 } //01 00  /goo/?a=%s
		$a_01_5 = {2f 67 6f 6f 67 6c 65 72 65 61 64 65 72 2f } //00 00  /googlereader/
	condition:
		any of ($a_*)
 
}