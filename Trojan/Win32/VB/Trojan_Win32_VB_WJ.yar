
rule Trojan_Win32_VB_WJ{
	meta:
		description = "Trojan:Win32/VB.WJ,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {3a 00 5c 00 44 00 6f 00 63 00 75 00 6d 00 65 00 6e 00 74 00 73 00 20 00 61 00 6e 00 64 00 20 00 53 00 65 00 74 00 74 00 69 00 6e 00 67 00 73 00 5c 00 75 00 73 00 75 00 61 00 72 00 69 00 6f 00 5c 00 4d 00 69 00 73 00 20 00 64 00 6f 00 63 00 75 00 6d 00 65 00 6e 00 74 00 6f 00 73 00 5c 00 53 00 43 00 72 00 79 00 70 00 74 00 65 00 72 00 5c 00 53 00 74 00 75 00 62 00 5c 00 53 00 43 00 50 00 2e 00 76 00 62 00 70 00 } //1 :\Documents and Settings\usuario\Mis documentos\SCrypter\Stub\SCP.vbp
	condition:
		((#a_01_0  & 1)*1) >=1
 
}