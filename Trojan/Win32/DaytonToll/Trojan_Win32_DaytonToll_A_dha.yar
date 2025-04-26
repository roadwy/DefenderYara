
rule Trojan_Win32_DaytonToll_A_dha{
	meta:
		description = "Trojan:Win32/DaytonToll.A!dha,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {31 38 32 4a 4b 57 4a 62 31 32 37 38 49 55 44 51 31 66 6e 6b 6c 32 38 39 21 40 5f 29 21 40 4b 4c 57 51 2a 28 21 40 4b 4c } //1 182JKWJb1278IUDQ1fnkl289!@_)!@KLWQ*(!@KL
	condition:
		((#a_01_0  & 1)*1) >=1
 
}