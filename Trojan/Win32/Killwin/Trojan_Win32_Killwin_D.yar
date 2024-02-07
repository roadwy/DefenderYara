
rule Trojan_Win32_Killwin_D{
	meta:
		description = "Trojan:Win32/Killwin.D,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {64 65 6c 20 25 73 79 73 74 65 6d 64 72 69 76 65 25 5c 6e 74 6c 64 72 } //01 00  del %systemdrive%\ntldr
		$a_01_1 = {64 65 6c 20 25 73 79 73 74 65 6d 64 72 69 76 65 25 5c 62 6f 6f 74 2e 69 6e 69 } //01 00  del %systemdrive%\boot.ini
		$a_01_2 = {73 68 75 74 64 6f 77 6e 20 2d 72 20 2d 74 20 31 35 20 2d 66 20 2d 63 20 22 42 79 65 2d 42 79 65 } //00 00  shutdown -r -t 15 -f -c "Bye-Bye
	condition:
		any of ($a_*)
 
}