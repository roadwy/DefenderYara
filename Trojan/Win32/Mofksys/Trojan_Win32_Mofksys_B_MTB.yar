
rule Trojan_Win32_Mofksys_B_MTB{
	meta:
		description = "Trojan:Win32/Mofksys.B!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {41 00 2a 00 5c 00 41 00 46 00 3a 00 5c 00 52 00 46 00 44 00 5c 00 78 00 4e 00 65 00 77 00 43 00 6f 00 64 00 65 00 5c 00 78 00 4e 00 65 00 77 00 50 00 72 00 6f 00 5c 00 78 00 54 00 5c 00 74 00 72 00 6a 00 46 00 4e 00 5c 00 50 00 72 00 6f 00 6a 00 65 00 63 00 74 00 31 00 2e 00 76 00 62 00 70 00 } //1 A*\AF:\RFD\xNewCode\xNewPro\xT\trjFN\Project1.vbp
	condition:
		((#a_01_0  & 1)*1) >=1
 
}