
rule Trojan_Win32_Aptdrop_L{
	meta:
		description = "Trojan:Win32/Aptdrop.L,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {43 3a 5c 55 73 65 72 73 5c 61 61 5c 44 6f 63 75 6d 65 6e 74 73 5c 56 69 73 75 61 6c 20 53 74 75 64 69 6f 20 32 30 31 35 5c 50 72 6f 6a 65 63 74 73 5c 61 67 65 6e 74 20 6b 20 6e 6f 76 5c 52 65 6c 65 61 73 65 5c 61 67 65 6e 74 20 6b 20 6e 6f 76 2e 70 64 62 } //1 C:\Users\aa\Documents\Visual Studio 2015\Projects\agent k nov\Release\agent k nov.pdb
	condition:
		((#a_01_0  & 1)*1) >=1
 
}