
rule Trojan_Win32_Covitse_AA_MTB{
	meta:
		description = "Trojan:Win32/Covitse.AA!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {73 6f 75 72 63 65 5c 72 65 70 6f 73 5c 43 6f 72 6f 6e 61 76 69 72 75 73 31 5c 43 6f 72 6f 6e 61 76 69 72 75 73 31 5c 6f 62 6a 5c 44 65 62 75 67 5c 43 6f 72 6f 6e 61 76 69 72 75 73 31 2e 70 64 62 } //1 source\repos\Coronavirus1\Coronavirus1\obj\Debug\Coronavirus1.pdb
	condition:
		((#a_01_0  & 1)*1) >=1
 
}