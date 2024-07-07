
rule Trojan_Win32_Zlob_AZ{
	meta:
		description = "Trojan:Win32/Zlob.AZ,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {67 6f 2d 61 76 61 73 74 7f e8 ff cb 21 00 67 61 72 62 61 67 65 77 6f 72 6c 64 23 62 6c 65 00 fe 77 53 9b 61 6f 76 48 61 74 68 13 41 70 70 6c 69 63 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}