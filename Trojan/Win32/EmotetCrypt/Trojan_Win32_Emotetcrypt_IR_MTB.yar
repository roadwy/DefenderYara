
rule Trojan_Win32_Emotetcrypt_IR_MTB{
	meta:
		description = "Trojan:Win32/Emotetcrypt.IR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 04 00 00 "
		
	strings :
		$a_01_0 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } //10 DllRegisterServer
		$a_01_1 = {5e 41 6c 77 65 24 66 36 59 61 66 71 41 51 31 52 46 6c 37 63 64 46 37 4f 35 70 30 44 67 3f 76 49 26 74 } //1 ^Alwe$f6YafqAQ1RFl7cdF7O5p0Dg?vI&t
		$a_01_2 = {4c 74 61 4c 30 50 31 4b 6f 47 3c 57 61 66 31 70 79 40 4b 33 78 55 73 68 6c 49 6b 4c 4e 37 3c 26 25 } //1 LtaL0P1KoG<Waf1py@K3xUshlIkLN7<&%
		$a_01_3 = {45 56 26 6e 6d 25 67 75 4b 57 58 3e 70 25 47 3f 4c 6d 66 61 41 3f 37 28 68 77 5f 39 56 3c 26 6c 4b 5e 23 77 71 3f 4f 79 35 4f } //1 EV&nm%guKWX>p%G?LmfaA?7(hw_9V<&lK^#wq?Oy5O
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=11
 
}