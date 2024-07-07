
rule Trojan_Win32_Vundo_FJ{
	meta:
		description = "Trojan:Win32/Vundo.FJ,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {74 5e 8b c6 50 e8 90 01 02 ff ff 90 00 } //2
		$a_01_1 = {2f 67 6f 2f 3f 63 6d 70 3d 68 73 74 77 74 63 68 } //1 /go/?cmp=hstwtch
		$a_01_2 = {72 65 64 5f 67 72 65 65 6e 5f 74 65 73 74 } //1 red_green_test
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}