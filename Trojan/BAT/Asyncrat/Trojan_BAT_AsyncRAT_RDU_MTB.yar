
rule Trojan_BAT_AsyncRAT_RDU_MTB{
	meta:
		description = "Trojan:BAT/AsyncRAT.RDU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {25 26 69 6f 90 01 04 25 26 13 04 09 90 00 } //2
		$a_01_1 = {57 69 6e 64 6f 77 73 20 50 6f 77 65 72 53 68 65 6c 6c } //1 Windows PowerShell
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}