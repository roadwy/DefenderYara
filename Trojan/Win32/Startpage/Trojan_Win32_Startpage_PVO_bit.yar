
rule Trojan_Win32_Startpage_PVO_bit{
	meta:
		description = "Trojan:Win32/Startpage.PVO!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 5c 4d 61 69 6e 5c 53 74 61 72 74 20 50 61 67 65 [0-10] 77 77 77 2e 32 33 34 35 2e 63 6f 6d 2f 3f 6b 37 34 34 36 30 36 36 34 30 } //1
		$a_01_1 = {56 4d 50 72 6f 74 65 63 74 20 62 65 67 69 6e } //1 VMProtect begin
		$a_01_2 = {00 57 54 57 69 6e 64 6f 77 00 } //1 圀坔湩潤w
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}