
rule Trojan_Win32_Emotetcrypt_IA_MTB{
	meta:
		description = "Trojan:Win32/Emotetcrypt.IA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_81_0 = {21 72 4e 4b 56 30 25 4d 57 3f 4f 79 41 4e 46 6e 3e 3c 74 76 44 6e 38 43 21 4e 4b 63 5f 58 28 2b 44 72 4c 63 36 73 49 72 4a 77 32 37 28 3c 2a 51 2a 46 5e } //1 !rNKV0%MW?OyANFn><tvDn8C!NKc_X(+DrLc6sIrJw27(<*Q*F^
		$a_81_1 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } //1 DllRegisterServer
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1) >=2
 
}