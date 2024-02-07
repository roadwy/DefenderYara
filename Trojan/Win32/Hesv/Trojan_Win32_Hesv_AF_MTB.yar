
rule Trojan_Win32_Hesv_AF_MTB{
	meta:
		description = "Trojan:Win32/Hesv.AF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {54 68 69 73 20 69 73 20 6c 61 73 74 20 77 61 72 6e 69 6e 67 2c 74 68 65 20 6d 61 6c 77 61 72 65 20 61 75 74 68 6f 72 20 63 6f 75 6c 64 6e 27 74 20 61 73 73 75 6d 65 20 6c 65 67 61 6c 20 6c 69 61 62 69 6c 69 74 79 2c 73 6f 20 61 72 65 20 79 6f 75 20 73 75 72 65 20 74 6f 20 72 75 6e 20 69 74 3f } //01 00  This is last warning,the malware author couldn't assume legal liability,so are you sure to run it?
		$a_01_1 = {54 68 69 73 20 4d 61 6c 77 61 72 65 20 77 69 6c 6c 20 64 69 73 74 75 72 62 20 79 6f 75 20 66 6f 72 20 73 6f 6d 65 20 74 69 6d 65 2c 61 72 65 20 79 6f 75 20 73 75 72 65 20 74 6f 20 72 75 6e 20 69 74 3f } //01 00  This Malware will disturb you for some time,are you sure to run it?
		$a_01_2 = {59 6f 75 20 61 72 65 20 61 20 49 64 69 6f 74 } //01 00  You are a Idiot
		$a_01_3 = {46 75 63 6b 20 59 6f 75 } //01 00  Fuck You
		$a_01_4 = {47 44 49 20 4d 61 6c 77 61 72 65 } //00 00  GDI Malware
	condition:
		any of ($a_*)
 
}