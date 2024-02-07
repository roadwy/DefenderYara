
rule Trojan_Win32_Radonskra_A{
	meta:
		description = "Trojan:Win32/Radonskra.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {64 2e 6c 6f 63 61 74 69 6f 6e 2e 70 72 6f 74 6f 63 6f 6c 3d 3d 27 68 74 74 70 73 3a 27 29 65 78 69 74 3b 6f 75 72 64 6f 6d 3d 27 68 74 74 70 3a } //01 00  d.location.protocol=='https:')exit;ourdom='http:
		$a_00_1 = {5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 73 79 73 74 65 6d 2e 65 78 65 } //01 00  \Microsoft\Windows\system.exe
		$a_00_2 = {2f 63 72 65 61 74 65 20 2f 74 6e 20 53 79 73 74 65 6d 53 63 72 69 70 74 20 2f 74 72 20 22 44 57 56 41 4c 55 45 22 20 2f 73 63 20 4f 4e 4c 4f 47 4f 4e 20 2f 66 } //01 00  /create /tn SystemScript /tr "DWVALUE" /sc ONLOGON /f
		$a_00_3 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 53 63 72 69 70 74 53 79 73 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Radonskra_A_2{
	meta:
		description = "Trojan:Win32/Radonskra.A,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {2f 64 65 6c 65 74 65 20 2f 74 6e 20 53 79 73 74 65 6d 53 63 72 69 70 74 20 2f 66 } //01 00  /delete /tn SystemScript /f
		$a_01_1 = {2f 63 72 65 61 74 65 20 2f 74 6e 20 53 79 73 74 65 6d 53 63 72 69 70 74 20 2f 74 72 20 22 44 57 56 41 4c 55 45 22 20 2f 73 63 20 4f 4e 4c 4f 47 4f 4e 20 2f 66 } //01 00  /create /tn SystemScript /tr "DWVALUE" /sc ONLOGON /f
		$a_01_2 = {70 6f 70 2e 6f 6b 69 6e 6f 66 69 6c 6d 2e 72 75 2f 72 75 2e 70 68 70 3f 73 6e 69 64 3d } //00 00  pop.okinofilm.ru/ru.php?snid=
	condition:
		any of ($a_*)
 
}