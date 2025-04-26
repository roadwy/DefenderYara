
rule Trojan_Win32_Separ_RB_MTB{
	meta:
		description = "Trojan:Win32/Separ.RB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {65 49 4f 52 4b 70 76 41 41 7a 59 65 31 65 68 36 70 64 72 32 44 65 6e 33 63 70 71 36 4d 6b 66 54 43 6a 53 51 78 64 71 6a 52 72 64 64 51 74 53 64 63 6d 56 4e 45 45 7a 54 4f 55 65 6e 6a 53 4d 33 36 4a 69 76 63 79 64 70 76 73 6f 56 71 79 4d 42 33 45 6b 31 4f 72 78 4f 41 66 5a 47 46 33 64 67 4a 38 61 30 48 57 44 53 4b 58 36 73 70 36 37 69 43 36 64 32 55 63 75 } //1 eIORKpvAAzYe1eh6pdr2Den3cpq6MkfTCjSQxdqjRrddQtSdcmVNEEzTOUenjSM36JivcydpvsoVqyMB3Ek1OrxOAfZGF3dgJ8a0HWDSKX6sp67iC6d2Ucu
		$a_01_1 = {6a 68 64 66 6b 6c 64 66 68 6e 64 66 6b 6a 64 66 6e 62 66 6b 6c 66 6e 66 } //1 jhdfkldfhndfkjdfnbfklfnf
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}