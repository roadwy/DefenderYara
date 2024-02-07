
rule Trojan_Win32_Yadditoe_A{
	meta:
		description = "Trojan:Win32/Yadditoe.A,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {67 6f 6f 64 2e 64 61 79 2e 74 6f 2e 64 69 65 } //01 00  good.day.to.die
		$a_01_1 = {2f 73 74 6f 72 65 2f 64 6e 73 63 6f 6e 66 69 67 2e 70 68 70 } //01 00  /store/dnsconfig.php
		$a_01_2 = {00 5c 63 6f 6e 66 69 67 67 67 2e 63 6f 6e 66 00 } //01 00  尀潣普杩杧挮湯f
		$a_01_3 = {50 49 44 3a 20 25 30 34 58 20 53 68 65 6c 6c 63 6f 64 65 20 69 6e 79 65 63 74 61 64 6f 20 65 6e 3a 20 25 70 2c 20 4d 6f 64 75 6c 6f 20 69 6e 79 65 63 74 61 64 6f 20 65 6e 3a 20 25 70 } //01 00  PID: %04X Shellcode inyectado en: %p, Modulo inyectado en: %p
		$a_01_4 = {46 69 6c 74 65 72 73 5b 69 5d 2e 61 64 64 72 65 73 73 20 25 73 20 46 69 6c 74 65 72 73 5b 69 5d 2e 74 6f 52 65 64 69 72 65 63 74 41 64 64 72 20 25 73 } //00 00  Filters[i].address %s Filters[i].toRedirectAddr %s
	condition:
		any of ($a_*)
 
}