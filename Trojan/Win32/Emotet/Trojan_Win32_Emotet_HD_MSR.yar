
rule Trojan_Win32_Emotet_HD_MSR{
	meta:
		description = "Trojan:Win32/Emotet.HD!MSR,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_01_0 = {54 72 6a 69 6d 6b 6c 6f 5c 52 65 6c 65 61 73 65 5c 54 52 4a 49 4d 4b 4c 4f 2e 70 64 62 } //1 Trjimklo\Release\TRJIMKLO.pdb
		$a_01_1 = {32 30 30 33 5c 45 66 65 6e 74 69 61 6c 5c 52 65 6c 65 61 73 65 5c 45 46 45 4e 54 49 41 4c 2e 70 64 62 } //1 2003\Efential\Release\EFENTIAL.pdb
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=1
 
}