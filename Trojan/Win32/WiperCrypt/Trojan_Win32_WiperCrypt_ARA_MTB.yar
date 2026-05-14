
rule Trojan_Win32_WiperCrypt_ARA_MTB{
	meta:
		description = "Trojan:Win32/WiperCrypt.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {ff d7 6a 00 8d 44 24 18 50 6a 04 8d 8c 24 68 01 00 00 51 56 ff d3 } //2
		$a_01_1 = {5c 45 58 45 5f 56 69 72 75 73 2e 70 64 62 } //2 \EXE_Virus.pdb
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}