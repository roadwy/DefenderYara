
rule Trojan_Win32_Emotetcrypt_JE_MTB{
	meta:
		description = "Trojan:Win32/Emotetcrypt.JE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 0a 00 "
		
	strings :
		$a_01_0 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } //01 00  DllRegisterServer
		$a_01_1 = {7a 54 73 73 61 3f 25 3c 74 69 36 51 40 41 61 3f 62 45 2b 6f 36 62 69 31 57 50 70 42 68 53 57 70 72 63 79 33 } //00 00  zTssa?%<ti6Q@Aa?bE+o6bi1WPpBhSWprcy3
	condition:
		any of ($a_*)
 
}