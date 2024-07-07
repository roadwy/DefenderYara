
rule Trojan_Win32_Tibs_IY{
	meta:
		description = "Trojan:Win32/Tibs.IY,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {38 31 2e 31 37 37 2e 32 36 2e 32 37 } //1 81.177.26.27
		$a_03_1 = {50 ff 75 10 be 90 01 02 40 00 56 e8 90 01 04 59 50 56 53 ff 15 90 01 02 40 00 ff 15 90 01 02 40 00 53 ff d7 ff 75 fc ff d7 5b ff 75 f8 ff d7 5f 5e c9 c3 90 00 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}