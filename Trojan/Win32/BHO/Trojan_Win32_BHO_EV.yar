
rule Trojan_Win32_BHO_EV{
	meta:
		description = "Trojan:Win32/BHO.EV,SIGNATURE_TYPE_PEHSTR,04 00 02 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {66 68 65 6c 70 2e 6b 72 } //01 00  fhelp.kr
		$a_01_1 = {73 69 72 63 68 65 63 6b 66 69 6c 65 2e 64 61 74 } //01 00  sircheckfile.dat
		$a_01_2 = {3f 00 70 00 6e 00 61 00 6d 00 65 00 3d 00 69 00 6f 00 6e 00 73 00 26 00 70 00 63 00 6f 00 64 00 65 00 3d 00 } //01 00  ?pname=ions&pcode=
		$a_01_3 = {5c 5f 49 45 42 72 6f 77 73 65 72 48 65 6c 70 65 72 2e 70 61 73 } //00 00  \_IEBrowserHelper.pas
	condition:
		any of ($a_*)
 
}