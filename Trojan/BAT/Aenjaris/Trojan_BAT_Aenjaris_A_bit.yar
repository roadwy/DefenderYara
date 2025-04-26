
rule Trojan_BAT_Aenjaris_A_bit{
	meta:
		description = "Trojan:BAT/Aenjaris.A!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {5c 56 69 72 75 73 20 50 72 6f 6a 65 74 6f 5c 52 65 6c 65 61 73 65 5c 54 65 73 74 65 2e 70 64 62 } //1 \Virus Projeto\Release\Teste.pdb
		$a_01_1 = {5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 53 74 61 72 74 20 4d 65 6e 75 5c 50 72 6f 67 72 61 6d 73 5c 53 74 61 72 74 75 70 5c } //1 \Microsoft\Windows\Start Menu\Programs\Startup\
		$a_01_2 = {73 65 72 76 65 72 6a 61 72 76 69 73 2e 73 79 74 65 73 2e 6e 65 74 2f 72 65 73 6f 75 72 63 65 5f 76 69 72 2f 63 6f 6d 6d 61 6e 64 2e 70 68 70 3f 76 65 72 73 69 6f 6e 3d } //1 serverjarvis.sytes.net/resource_vir/command.php?version=
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}