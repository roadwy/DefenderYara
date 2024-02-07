
rule Trojan_Win32_ObserverStealer_A_MTB{
	meta:
		description = "Trojan:Win32/ObserverStealer.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 04 00 00 02 00 "
		
	strings :
		$a_01_0 = {70 00 72 00 6f 00 63 00 65 00 73 00 73 00 47 00 72 00 61 00 62 00 62 00 65 00 72 00 } //02 00  processGrabber
		$a_01_1 = {65 6e 63 72 79 70 74 65 64 50 61 73 73 77 6f 72 64 22 3a 22 28 5b } //02 00  encryptedPassword":"([
		$a_01_2 = {68 6f 73 74 6e 61 6d 65 22 3a 22 28 5b } //02 00  hostname":"([
		$a_01_3 = {65 6e 63 72 79 70 74 65 64 5f 6b 65 79 22 3a 22 28 2e 2b 3f 29 } //00 00  encrypted_key":"(.+?)
	condition:
		any of ($a_*)
 
}