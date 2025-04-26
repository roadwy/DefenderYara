
rule Ransom_MSIL_Gansom_AA_MSR{
	meta:
		description = "Ransom:MSIL/Gansom.AA!MSR,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {72 65 70 6f 73 5c 52 61 6e 73 6f 6d 77 61 72 65 5c 52 61 6e 73 6f 6d 77 61 72 65 5c 6f 62 6a 5c 44 65 62 75 67 5c 52 61 6e 73 6f 6d 77 61 72 65 2e 70 64 62 } //1 repos\Ransomware\Ransomware\obj\Debug\Ransomware.pdb
		$a_01_1 = {52 61 6e 73 6f 6d 77 61 72 65 2e 65 78 65 } //1 Ransomware.exe
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}