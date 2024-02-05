
rule Trojan_Win32_Raspberryrobin_RB_MTB{
	meta:
		description = "Trojan:Win32/Raspberryrobin.RB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {52 78 64 74 63 79 4f 69 6e 75 62 } //01 00 
		$a_01_1 = {53 72 65 72 72 74 74 72 74 48 75 6e 69 6d } //01 00 
		$a_01_2 = {4f 69 6e 75 66 47 63 72 74 76 79 62 } //00 00 
	condition:
		any of ($a_*)
 
}