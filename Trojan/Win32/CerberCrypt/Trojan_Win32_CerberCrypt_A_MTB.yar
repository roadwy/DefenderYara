
rule Trojan_Win32_CerberCrypt_A_MTB{
	meta:
		description = "Trojan:Win32/CerberCrypt.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {8a 06 32 c2 88 07 42 46 47 e9 } //2
		$a_01_1 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 } //1 VirtualAlloc
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}