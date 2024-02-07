
rule Trojan_Win32_Trickbot_STP_dll{
	meta:
		description = "Trojan:Win32/Trickbot.STP!dll,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {4e 45 54 57 4f 52 4b 44 4c 4c } //01 00  NETWORKDLL
		$a_80_1 = {3c 6d 6f 64 75 6c 65 63 6f 6e 66 69 67 3e 3c 6e 65 65 64 69 6e 66 6f 20 6e 61 6d 65 } //<moduleconfig><needinfo name  01 00 
		$a_80_2 = {47 72 61 62 62 65 72 20 73 74 61 72 74 65 64 } //Grabber started  01 00 
		$a_80_3 = {6e 6c 74 65 73 74 20 2f 64 6f 6d 61 69 6e 5f 74 72 75 73 74 73 } //nltest /domain_trusts  00 00 
		$a_00_4 = {5d 04 00 } //00 9f 
	condition:
		any of ($a_*)
 
}