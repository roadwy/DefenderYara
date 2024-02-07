
rule Backdoor_Win32_RDPdoor_A{
	meta:
		description = "Backdoor:Win32/RDPdoor.A,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 04 00 00 02 00 "
		
	strings :
		$a_01_0 = {53 59 53 54 45 4d 5c 43 75 72 72 65 6e 74 43 6f 6e 74 72 6f 6c 53 65 74 5c 43 6f 6e 74 72 6f 6c 5c 54 65 72 6d 69 6e 61 6c 20 53 65 72 76 65 72 5c 57 69 6e 53 74 61 74 69 6f 6e 73 5c 52 44 50 2d 54 63 70 } //04 00  SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp
		$a_01_1 = {50 53 57 3a 20 53 65 6e 64 20 66 6c 61 67 73 20 72 65 73 65 74 65 64 } //02 00  PSW: Send flags reseted
		$a_01_2 = {4b 61 73 70 65 72 73 6b 79 20 41 6e 74 69 2d 48 61 63 6b 65 72 2e 6c 6e 6b } //04 00  Kaspersky Anti-Hacker.lnk
		$a_01_3 = {52 4e 47 55 56 40 53 44 5d 4c 68 62 73 6e 72 6e 67 75 5d 56 68 6f 65 6e 76 72 5d 42 74 73 73 64 6f 75 57 64 73 72 68 6e 6f 5d 53 74 6f } //00 00  RNGUV@SD]Lhbsnrngu]Vhoenvr]BtssdouWdsrhno]Sto
	condition:
		any of ($a_*)
 
}