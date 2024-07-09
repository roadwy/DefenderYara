
rule Trojan_Win64_Trickrdp_B_MTB{
	meta:
		description = "Trojan:Win64/Trickrdp.B!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_80_0 = {72 64 70 73 63 61 6e 2e 64 6c 6c } //rdpscan.dll  1
		$a_80_1 = {46 3a 5c 72 64 70 73 63 61 6e 5c 42 69 6e 5c 52 65 6c 65 61 73 65 5f 6c 6f 67 67 65 64 5c 78 36 34 5c 72 64 70 73 63 61 6e 2e 70 64 62 } //F:\rdpscan\Bin\Release_logged\x64\rdpscan.pdb  1
		$a_02_2 = {46 72 65 65 42 75 66 66 65 72 [0-04] 52 65 6c 65 61 73 65 [0-04] 53 74 61 72 74 } //1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_02_2  & 1)*1) >=3
 
}