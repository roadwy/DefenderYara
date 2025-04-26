
rule Trojan_Win64_Trickbot_AC_MTB{
	meta:
		description = "Trojan:Win64/Trickbot.AC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 07 00 00 "
		
	strings :
		$a_80_0 = {6d 61 73 74 65 72 20 73 65 63 72 65 74 } //master secret  3
		$a_80_1 = {31 2e 33 2e 36 2e 31 2e 35 2e 35 2e 37 2e 33 2e 31 } //1.3.6.1.5.5.7.3.1  3
		$a_80_2 = {78 34 35 62 63 37 31 39 66 65 30 31 2e 31 33 } //x45bc719fe01.13  3
		$a_80_3 = {41 64 64 56 65 63 74 6f 72 65 64 45 78 63 65 70 74 69 6f 6e 48 61 6e 64 6c 65 72 } //AddVectoredExceptionHandler  3
		$a_80_4 = {47 65 74 50 72 6f 63 65 73 73 41 66 66 69 6e 69 74 79 4d 61 73 6b } //GetProcessAffinityMask  3
		$a_80_5 = {50 52 49 20 2a 20 48 54 54 50 2f 32 2e 30 } //PRI * HTTP/2.0  3
		$a_80_6 = {63 6c 69 65 6e 74 20 66 69 6e 69 73 68 65 64 } //client finished  3
	condition:
		((#a_80_0  & 1)*3+(#a_80_1  & 1)*3+(#a_80_2  & 1)*3+(#a_80_3  & 1)*3+(#a_80_4  & 1)*3+(#a_80_5  & 1)*3+(#a_80_6  & 1)*3) >=21
 
}