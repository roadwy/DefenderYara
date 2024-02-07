
rule Trojan_Win32_MKLKlog_A{
	meta:
		description = "Trojan:Win32/MKLKlog.A,SIGNATURE_TYPE_PEHSTR,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {4d 2e 4b 2e 4c 2e } //01 00  M.K.L.
		$a_01_1 = {73 6f 66 74 77 61 72 65 5c 6d 69 63 72 6f 73 6f 66 74 5c 77 69 6e 64 6f 77 73 5c 63 75 72 72 65 6e 74 76 65 72 73 69 6f 6e 5c 72 75 6e } //01 00  software\microsoft\windows\currentversion\run
		$a_01_2 = {6e 65 74 73 68 2e 65 78 65 20 66 69 72 65 77 61 6c 6c 20 61 64 64 20 61 6c 6c 6f 77 65 64 70 72 6f 67 72 61 6d 20 25 73 20 57 69 6e 46 69 72 65 77 61 6c 6c } //01 00  netsh.exe firewall add allowedprogram %s WinFirewall
		$a_01_3 = {4c 49 42 47 43 43 57 33 32 2d 45 48 2d 32 2d 53 4a 4c 4a 2d 47 54 48 52 2d 4d 49 4e 47 57 33 32 } //01 00  LIBGCCW32-EH-2-SJLJ-GTHR-MINGW32
		$a_01_4 = {67 73 6d 74 70 31 38 35 2e 67 6f 6f 67 6c 65 2e 63 6f 6d } //00 00  gsmtp185.google.com
	condition:
		any of ($a_*)
 
}