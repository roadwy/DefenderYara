
rule Ransom_Linux_Sodinokibi_JJ{
	meta:
		description = "Ransom:Linux/Sodinokibi.JJ,SIGNATURE_TYPE_ELFHSTR_EXT,04 00 04 00 06 00 00 01 00 "
		
	strings :
		$a_00_0 = {65 73 78 63 6c 69 20 2d 2d 66 6f 72 6d 61 74 74 65 72 3d 63 73 76 20 2d 2d 66 6f 72 6d 61 74 2d 70 61 72 61 6d 3d 66 69 65 6c 64 73 3d 3d } //01 00  esxcli --formatter=csv --format-param=fields==
		$a_00_1 = {76 6d 20 70 72 6f 63 65 73 73 20 6c 69 73 74 20 7c 20 61 77 6b 20 2d 46 20 } //01 00  vm process list | awk -F 
		$a_00_2 = {65 73 78 63 6c 69 20 76 6d 20 70 72 6f 63 65 73 73 20 6b 69 6c 6c 20 2d 2d 74 79 70 65 3d 66 6f 72 63 65 20 2d 2d 77 6f 72 6c 64 2d 69 64 3d } //01 00  esxcli vm process kill --type=force --world-id=
		$a_00_3 = {52 65 76 69 78 20 31 2e 31 } //01 00  Revix 1.1
		$a_00_4 = {21 21 21 42 59 20 44 45 46 41 55 4c 54 20 54 48 49 53 20 53 4f 46 54 57 41 52 45 20 55 53 45 53 20 35 30 20 54 48 52 45 41 44 53 21 21 21 } //01 00  !!!BY DEFAULT THIS SOFTWARE USES 50 THREADS!!!
		$a_00_5 = {55 73 69 6e 67 20 73 69 6c 65 6e 74 20 6d 6f 64 65 2c 20 69 66 20 79 6f 75 20 6f 6e 20 65 73 78 69 20 2d 20 73 74 6f 70 20 56 4d 73 20 6d 61 6e 75 61 6c 79 } //00 00  Using silent mode, if you on esxi - stop VMs manualy
		$a_00_6 = {5d 04 } //00 00  ѝ
	condition:
		any of ($a_*)
 
}