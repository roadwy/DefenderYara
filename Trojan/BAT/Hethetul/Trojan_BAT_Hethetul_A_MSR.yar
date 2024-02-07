
rule Trojan_BAT_Hethetul_A_MSR{
	meta:
		description = "Trojan:BAT/Hethetul.A!MSR,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {07 0c 02 08 8f 7d 00 00 01 25 71 7d 00 00 01 06 07 1f 0a 5d 91 61 d2 81 7d 00 00 01 07 17 58 0b 07 02 8e 69 32 da 02 2a } //01 00 
		$a_01_1 = {55 73 65 72 73 5c 48 61 63 20 54 6f 6f 4c 5c 44 65 73 6b 74 6f 70 5c 48 65 74 5c 48 65 74 } //00 00  Users\Hac TooL\Desktop\Het\Het
	condition:
		any of ($a_*)
 
}