
rule Trojan_Win32_Crysteb_B{
	meta:
		description = "Trojan:Win32/Crysteb.B,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {65 78 74 2d 74 65 73 74 2d 65 31 37 31 38 2e 66 69 72 65 62 61 73 65 61 70 70 2e 63 6f 6d } //00 00  ext-test-e1718.firebaseapp.com
	condition:
		any of ($a_*)
 
}