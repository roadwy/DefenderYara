
rule Trojan_Win32_Nottap_B{
	meta:
		description = "Trojan:Win32/Nottap.B,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_80_0 = {2d 2d 61 64 63 73 20 3c 63 73 20 73 65 72 76 65 72 3e } //--adcs <cs server>  1
		$a_80_1 = {2f 63 65 72 74 73 72 76 2f 63 65 72 74 66 6e 73 68 2e 61 73 70 } ///certsrv/certfnsh.asp  1
		$a_80_2 = {26 43 65 72 74 41 74 74 72 69 62 3d 43 65 72 74 69 66 69 63 61 74 65 54 65 6d 70 6c 61 74 65 3a } //&CertAttrib=CertificateTemplate:  1
		$a_80_3 = {52 65 6c 61 79 69 6e 67 20 4e 54 4c 4d 53 53 50 5f 43 48 41 4c 4c 45 4e 47 45 20 74 6f 20 63 6c 69 65 6e 74 } //Relaying NTLMSSP_CHALLENGE to client  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1) >=3
 
}