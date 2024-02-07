
rule Trojan_Win32_Minpaidus_B{
	meta:
		description = "Trojan:Win32/Minpaidus.B,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_00_0 = {3a 00 5c 00 66 00 61 00 64 00 6c 00 79 00 5c 00 55 00 6e 00 63 00 6c 00 6f 00 73 00 65 00 5c 00 55 00 6e 00 63 00 6c 00 6f 00 73 00 65 00 5c 00 4c 00 69 00 62 00 5c 00 55 00 6e 00 63 00 6c 00 6f 00 73 00 65 00 2e 00 76 00 62 00 70 00 } //01 00  :\fadly\Unclose\Unclose\Lib\Unclose.vbp
		$a_01_1 = {00 48 6f 6f 6b 46 75 6e 63 74 69 6f 6e 00 52 65 64 69 72 65 63 74 4f 70 65 6e 50 72 6f 63 65 73 73 00 } //00 00  䠀潯䙫湵瑣潩n敒楤敲瑣灏湥牐捯獥s
	condition:
		any of ($a_*)
 
}