
rule Trojan_Win32_Fareit_AFA_MTB{
	meta:
		description = "Trojan:Win32/Fareit.AFA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {6a 00 e8 f8 1e fc ff e8 1b 1e fc ff 2b c3 3d e8 03 00 00 } //1
		$a_03_1 = {b9 5e 34 2f 1c 33 d2 8b c3 e8 90 01 04 89 45 fc e8 90 01 04 68 00 80 00 00 6a 00 53 90 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}