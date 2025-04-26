
rule Ransom_MSIL_Springbeep_A_bit{
	meta:
		description = "Ransom:MSIL/Springbeep.A!bit,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {5c 00 77 00 69 00 6e 00 6c 00 6f 00 61 00 64 00 2e 00 62 00 69 00 6e 00 } //1 \winload.bin
		$a_01_1 = {5c 00 63 00 6d 00 64 00 74 00 6f 00 6f 00 6c 00 2e 00 65 00 78 00 65 00 } //1 \cmdtool.exe
		$a_01_2 = {5c 00 53 00 70 00 72 00 69 00 6e 00 67 00 62 00 65 00 65 00 70 00 2e 00 6c 00 6f 00 63 00 6b 00 } //1 \Springbeep.lock
		$a_01_3 = {2f 00 41 00 75 00 74 00 6f 00 72 00 75 00 6e 00 } //1 /Autorun
		$a_01_4 = {5c 52 65 6c 65 61 73 65 5c 53 70 72 69 6e 67 62 65 65 70 2e 70 64 62 } //1 \Release\Springbeep.pdb
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}