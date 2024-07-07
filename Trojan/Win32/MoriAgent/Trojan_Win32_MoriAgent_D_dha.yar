
rule Trojan_Win32_MoriAgent_D_dha{
	meta:
		description = "Trojan:Win32/MoriAgent.D!dha,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {01 00 46 4d 4c 2e 64 6c 6c 00 44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 00 44 6c 6c 55 6e 72 65 67 69 73 74 65 72 53 65 72 76 65 72 00 00 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}