
rule Trojan_Win32_Gozi_A{
	meta:
		description = "Trojan:Win32/Gozi.A,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {79 3a 5c 73 2d 6d 61 73 74 65 72 5c 76 63 6c 5c 61 64 63 73 5c 72 65 6c 65 61 73 65 5c 4c 4f 47 45 53 53 53 53 2e 70 64 62 } //1 y:\s-master\vcl\adcs\release\LOGESSSS.pdb
	condition:
		((#a_01_0  & 1)*1) >=1
 
}