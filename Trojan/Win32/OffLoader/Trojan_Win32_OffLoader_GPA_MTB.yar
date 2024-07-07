
rule Trojan_Win32_OffLoader_GPA_MTB{
	meta:
		description = "Trojan:Win32/OffLoader.GPA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 04 00 00 "
		
	strings :
		$a_80_0 = {76 65 73 74 6d 6f 75 6e 74 61 69 6e 2e 73 69 74 65 2f 62 6c 69 2e 70 68 70 } //vestmountain.site/bli.php  5
		$a_80_1 = {77 6f 6f 64 6c 65 76 65 6c 2e 73 69 74 65 2f 74 72 61 63 6b 65 72 2f 74 68 61 6e 6b 5f 79 6f 75 2e 70 68 70 } //woodlevel.site/tracker/thank_you.php  2
		$a_80_2 = {73 65 65 64 61 67 72 65 65 6d 65 6e 74 2e 73 69 74 65 2f 61 73 69 6b 6f 2e 70 68 70 } //seedagreement.site/asiko.php  5
		$a_80_3 = {73 74 6f 2e 66 61 72 6d 73 63 65 6e 65 2e 77 65 62 73 69 74 65 } //sto.farmscene.website  2
	condition:
		((#a_80_0  & 1)*5+(#a_80_1  & 1)*2+(#a_80_2  & 1)*5+(#a_80_3  & 1)*2) >=7
 
}