
rule Trojan_Win32_Dridex_dwuq_MTB{
	meta:
		description = "Trojan:Win32/Dridex.dwuq!MTB,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 08 00 00 02 00 "
		
	strings :
		$a_80_0 = {68 74 74 70 3a 2f 2f 77 77 77 2e 62 65 73 74 68 6f 74 65 6c 33 36 30 2e 63 6f 6d 3a 31 32 31 39 2f 30 30 31 2f 70 75 70 70 65 74 2e 54 78 74 } //http://www.besthotel360.com:1219/001/puppet.Txt  02 00 
		$a_80_1 = {68 74 74 70 2f 31 2e 31 } //http/1.1  02 00 
		$a_80_2 = {68 74 74 70 2f 31 2e 30 } //http/1.0  02 00 
		$a_80_3 = {65 4c 67 6d 70 48 78 75 4e 31 6a 34 6f 45 63 65 4c 67 6d 70 48 78 75 4e 31 6a 34 6f 45 63 65 4c 67 6d 70 48 78 75 4e 31 6a 34 6f 45 63 } //eLgmpHxuN1j4oEceLgmpHxuN1j4oEceLgmpHxuN1j4oEc  02 00 
		$a_80_4 = {59 63 52 74 75 4e 6a 6d 54 30 62 31 59 63 52 74 75 4e 6a 6d 54 30 62 31 59 63 52 74 75 4e 6a 6d 54 30 62 31 } //YcRtuNjmT0b1YcRtuNjmT0b1YcRtuNjmT0b1  02 00 
		$a_80_5 = {4f 47 62 32 47 4b 5a 73 4f 47 62 32 47 4b 5a 73 4f 47 62 32 47 4b 5a 73 } //OGb2GKZsOGb2GKZsOGb2GKZs  02 00 
		$a_80_6 = {48 6f 55 53 67 4d 33 43 5a 48 6f 55 53 67 4d 33 43 5a 48 6f 55 53 67 4d 33 43 5a } //HoUSgM3CZHoUSgM3CZHoUSgM3CZ  02 00 
		$a_80_7 = {36 54 54 48 72 36 54 54 48 72 36 54 54 48 72 } //6TTHr6TTHr6TTHr  00 00 
	condition:
		any of ($a_*)
 
}