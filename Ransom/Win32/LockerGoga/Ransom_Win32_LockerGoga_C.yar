
rule Ransom_Win32_LockerGoga_C{
	meta:
		description = "Ransom:Win32/LockerGoga.C,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {77 6f 72 6b 5c 50 72 6f 6a 65 63 74 73 5c 4c 6f 63 6b 65 72 47 6f 67 61 } //1 work\Projects\LockerGoga
		$a_01_1 = {43 00 72 00 79 00 70 00 74 00 6f 00 4c 00 6f 00 63 00 6b 00 65 00 72 00 } //1 CryptoLocker
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}