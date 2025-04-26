
rule Trojan_Win32_Offloader_B_MTB{
	meta:
		description = "Trojan:Win32/Offloader.B!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_01_0 = {3a 00 2f 00 2f 00 77 00 6f 00 6f 00 64 00 6c 00 65 00 76 00 65 00 6c 00 2e 00 73 00 69 00 74 00 65 00 2f 00 74 00 72 00 61 00 63 00 6b 00 65 00 72 00 2f 00 74 00 68 00 61 00 6e 00 6b 00 5f 00 79 00 6f 00 75 00 2e 00 70 00 68 00 70 00 3f 00 } //2 ://woodlevel.site/tracker/thank_you.php?
		$a_01_1 = {3a 00 2f 00 2f 00 76 00 65 00 73 00 74 00 6d 00 6f 00 75 00 6e 00 74 00 61 00 69 00 6e 00 2e 00 73 00 69 00 74 00 65 00 2f 00 62 00 6c 00 69 00 2e 00 70 00 68 00 70 00 3f 00 } //2 ://vestmountain.site/bli.php?
		$a_01_2 = {2f 00 73 00 69 00 6c 00 65 00 6e 00 74 00 } //1 /silent
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1) >=5
 
}