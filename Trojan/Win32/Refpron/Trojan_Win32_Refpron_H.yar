
rule Trojan_Win32_Refpron_H{
	meta:
		description = "Trojan:Win32/Refpron.H,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {6d ce 8b c0 bf 58 8b c0 } //1
		$a_02_1 = {ff d0 3d 02 01 00 00 75 90 14 b3 01 33 c0 } //1
		$a_01_2 = {2e 64 6c 6c 00 53 65 72 76 69 63 65 4d 61 69 6e 00 72 00 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_02_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}