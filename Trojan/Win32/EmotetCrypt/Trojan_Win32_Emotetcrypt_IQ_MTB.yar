
rule Trojan_Win32_Emotetcrypt_IQ_MTB{
	meta:
		description = "Trojan:Win32/Emotetcrypt.IQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_81_0 = {4d 53 6d 72 30 29 50 5f 69 30 44 48 56 30 52 6a 55 52 6c 64 79 73 46 52 4e 50 39 3e 61 4b 48 64 75 37 23 6c 4c 59 23 68 47 6c 57 75 44 56 3e 5e 6a 6a 6f 21 34 52 2b 45 70 36 53 64 6e 40 79 4e 23 48 40 6d 21 61 41 56 2a 43 49 52 77 3f 29 } //01 00  MSmr0)P_i0DHV0RjURldysFRNP9>aKHdu7#lLY#hGlWuDV>^jjo!4R+Ep6Sdn@yN#H@m!aAV*CIRw?)
		$a_81_1 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } //00 00  DllRegisterServer
	condition:
		any of ($a_*)
 
}