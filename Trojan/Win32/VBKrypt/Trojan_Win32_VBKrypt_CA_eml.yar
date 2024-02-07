
rule Trojan_Win32_VBKrypt_CA_eml{
	meta:
		description = "Trojan:Win32/VBKrypt.CA!eml,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {63 00 61 00 63 00 49 00 4f 00 54 00 54 00 4f 00 4e 00 61 00 6c 00 69 00 62 00 65 00 72 00 61 00 } //01 00  cacIOTTONalibera
		$a_01_1 = {63 00 6f 00 6e 00 74 00 72 00 6f 00 72 00 41 00 58 00 2e 00 65 00 78 00 65 00 } //00 00  controrAX.exe
	condition:
		any of ($a_*)
 
}