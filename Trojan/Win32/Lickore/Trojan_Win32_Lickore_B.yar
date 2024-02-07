
rule Trojan_Win32_Lickore_B{
	meta:
		description = "Trojan:Win32/Lickore.B,SIGNATURE_TYPE_PEHSTR_EXT,05 00 04 00 04 00 00 02 00 "
		
	strings :
		$a_03_0 = {8b 55 f4 b1 01 8b 45 f8 e8 90 01 04 84 c0 74 90 01 01 8b 45 f8 e8 90 01 04 ba 00 00 00 80 8b 45 f8 e8 90 01 04 8d 45 f0 90 00 } //01 00 
		$a_00_1 = {63 6c 69 63 6b 73 74 6f 72 79 2e 63 6f 2e 6b 72 2f 3f } //01 00  clickstory.co.kr/?
		$a_00_2 = {63 6c 69 63 6b 2e 6c 69 6e 6b 70 72 69 63 65 2e 63 6f 6d 2f 63 6c 69 63 6b 2e 70 68 70 3f 6d 3d } //01 00  click.linkprice.com/click.php?m=
		$a_03_3 = {6a 61 76 61 73 63 72 69 70 74 3a 90 02 20 61 62 6f 75 74 3a 62 6c 61 6e 6b 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}