
rule Trojan_Win32_ArkeiStealer_A{
	meta:
		description = "Trojan:Win32/ArkeiStealer.A,SIGNATURE_TYPE_PEHSTR,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {72 65 67 20 64 65 6c 65 74 65 20 22 48 4b 4c 4d 5c 53 6f 66 74 77 61 72 65 5c 50 6f 6c 69 63 69 65 73 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 20 44 65 66 65 6e 64 65 72 22 20 2f 66 } //1 reg delete "HKLM\Software\Policies\Microsoft\Windows Defender" /f
		$a_01_1 = {4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 20 44 65 66 65 6e 64 65 72 5c 52 65 61 6c 2d 54 69 6d 65 20 50 72 6f 74 65 63 74 69 6f 6e } //1 Microsoft\Windows Defender\Real-Time Protection
		$a_01_2 = {4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 20 44 65 66 65 6e 64 65 72 5c 4d 70 45 6e 67 69 6e 65 22 20 2f 76 20 22 4d 70 45 6e 61 62 6c 65 50 75 73 } //1 Microsoft\Windows Defender\MpEngine" /v "MpEnablePus
		$a_01_3 = {22 63 61 6d 22 3a 20 74 72 75 65 2c } //1 "cam": true,
		$a_01_4 = {22 66 69 6c 65 73 22 3a 20 66 61 6c 73 65 2c } //1 "files": false,
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}