
rule Trojan_Win32_CryptInject_Y{
	meta:
		description = "Trojan:Win32/CryptInject.Y,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {e8 b8 d0 00 00 e9 7f fe ff ff cc cc cc cc cc cc cc cc cc cc cc cc 57 56 8b 74 24 10 8b 4c 24 14 8b 7c 24 0c } //01 00 
		$a_01_1 = {46 30 46 32 31 33 42 30 37 39 39 31 39 37 46 44 31 31 39 31 37 31 36 38 30 45 43 37 39 43 41 39 31 } //00 00  F0F213B0799197FD119171680EC79CA91
	condition:
		any of ($a_*)
 
}