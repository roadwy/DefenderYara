
rule Trojan_WinNT_Parchood_A{
	meta:
		description = "Trojan:WinNT/Parchood.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {74 0e c7 05 90 09 09 00 ff ff ff d0 3d 0b 01 00 00 } //1
		$a_03_1 = {e4 50 8d 05 90 09 0f 00 6a 00 6a 00 8d 45 e8 50 68 ff 03 1f 00 8d 45 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}