
rule Trojan_Win32_Cadlotcorg_B_dha{
	meta:
		description = "Trojan:Win32/Cadlotcorg.B!dha,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {2f 00 64 00 65 00 73 00 74 00 72 00 6f 00 79 00 6f 00 73 00 } //1 /destroyos
		$a_01_1 = {2f 00 64 00 65 00 73 00 74 00 72 00 6f 00 79 00 75 00 73 00 62 00 } //1 /destroyusb
		$a_01_2 = {5c 5c 2e 5c 50 68 79 73 69 63 61 6c 44 72 69 76 65 } //1 \\.\PhysicalDrive
		$a_01_3 = {43 00 3a 00 5c 00 50 00 72 00 6f 00 67 00 72 00 61 00 6d 00 20 00 46 00 69 00 6c 00 65 00 73 00 5c 00 2a 00 } //1 C:\Program Files\*
		$a_01_4 = {43 00 3a 00 5c 00 50 00 72 00 6f 00 67 00 72 00 61 00 6d 00 20 00 46 00 69 00 6c 00 65 00 73 00 5c 00 43 00 6f 00 6d 00 6d 00 6f 00 6e 00 20 00 46 00 69 00 6c 00 65 00 73 00 5c 00 53 00 79 00 73 00 74 00 65 00 6d 00 5c 00 2a 00 } //1 C:\Program Files\Common Files\System\*
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}