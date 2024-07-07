
rule Adware_Win32_Ndmser_A{
	meta:
		description = "Adware:Win32/Ndmser.A,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 3a 2f 2f 6e 74 68 6e 75 65 73 74 2e 63 6f 6d 3a 34 30 30 30 30 2f 74 69 63 6b 65 74 73 } //1 http://nthnuest.com:40000/tickets
	condition:
		((#a_01_0  & 1)*1) >=1
 
}