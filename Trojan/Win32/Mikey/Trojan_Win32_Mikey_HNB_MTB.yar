
rule Trojan_Win32_Mikey_HNB_MTB{
	meta:
		description = "Trojan:Win32/Mikey.HNB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {6d 6f 64 65 2e 0d 0d 0a 24 00 00 00 00 00 00 00 65 0d a3 87 21 6c cd d4 21 6c cd d4 21 6c cd d4 af 73 de d4 2b 6c cd d4 21 6c cd d4 20 6c cd d4 52 69 63 68 21 6c cd d4 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 50 45 00 00 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}