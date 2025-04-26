
rule Trojan_Win32_Taidoor_C_dha{
	meta:
		description = "Trojan:Win32/Taidoor.C!dha,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 01 00 00 "
		
	strings :
		$a_01_0 = {4d 65 6d 6f 72 79 4c 6f 61 64 2e 64 6c 6c 00 4d 79 53 74 61 72 74 00 53 65 72 76 69 63 65 4d 61 69 6e 00 } //3
	condition:
		((#a_01_0  & 1)*3) >=3
 
}