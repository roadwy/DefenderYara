
rule Trojan_Win32_Tracur_AF{
	meta:
		description = "Trojan:Win32/Tracur.AF,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {3d 2e 6a 70 67 74 } //1 =.jpgt
		$a_01_1 = {8b 45 08 8d 40 18 50 } //1
		$a_03_2 = {8b 45 0c ff 10 83 c4 90 09 02 00 54 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}