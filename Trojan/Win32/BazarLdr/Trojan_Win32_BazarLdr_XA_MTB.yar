
rule Trojan_Win32_BazarLdr_XA_MTB{
	meta:
		description = "Trojan:Win32/BazarLdr.XA!MTB,SIGNATURE_TYPE_PEHSTR,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {50 00 72 00 6f 00 63 00 65 00 73 00 73 00 20 00 44 00 6f 00 70 00 70 00 65 00 6c 00 67 00 61 00 6e 00 67 00 69 00 6e 00 67 00 20 00 74 00 65 00 73 00 74 00 } //1 Process Doppelganging test
		$a_01_1 = {43 61 6e 6e 6f 74 20 72 65 61 64 20 72 65 6d 6f 74 65 20 50 45 42 } //1 Cannot read remote PEB
		$a_01_2 = {53 00 48 00 41 00 33 00 38 00 34 00 } //1 SHA384
		$a_01_3 = {62 63 72 79 70 74 2e 64 6c 6c } //1 bcrypt.dll
		$a_01_4 = {43 72 79 70 74 53 74 72 69 6e 67 54 6f 42 69 6e 61 72 79 41 } //1 CryptStringToBinaryA
		$a_01_5 = {43 72 79 70 74 41 63 71 75 69 72 65 43 6f 6e 74 65 78 74 41 } //1 CryptAcquireContextA
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}