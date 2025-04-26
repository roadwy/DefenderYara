
rule Trojan_Win32_Dialer_SGA_MTB{
	meta:
		description = "Trojan:Win32/Dialer.SGA!MTB,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {5c 50 72 6f 67 72 61 6d 20 46 69 6c 65 73 5c 44 69 61 6c 65 72 73 } //1 \Program Files\Dialers
		$a_01_1 = {44 69 73 61 62 6c 65 43 61 6c 6c 57 61 69 74 69 6e 67 } //1 DisableCallWaiting
		$a_01_2 = {52 61 73 44 69 61 6c 41 } //1 RasDialA
		$a_01_3 = {47 54 6f 6f 6c 73 33 32 20 2d 20 49 6e 73 74 61 6c 6c 4d 49 4d 45 } //1 GTools32 - InstallMIME
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}