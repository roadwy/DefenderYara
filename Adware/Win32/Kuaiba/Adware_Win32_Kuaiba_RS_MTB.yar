
rule Adware_Win32_Kuaiba_RS_MTB{
	meta:
		description = "Adware:Win32/Kuaiba.RS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_80_0 = {72 75 6e 34 35 36 2e 63 6f 6d } //run456.com  01 00 
		$a_80_1 = {6b 75 61 69 38 2e 63 6f 6d } //kuai8.com  01 00 
		$a_80_2 = {6b 75 61 69 38 5f 66 6f 72 5f 69 6e 73 74 61 6c 6c 65 72 2e 65 78 65 } //kuai8_for_installer.exe  01 00 
		$a_80_3 = {47 61 6d 65 73 74 61 72 74 } //Gamestart  00 00 
	condition:
		any of ($a_*)
 
}