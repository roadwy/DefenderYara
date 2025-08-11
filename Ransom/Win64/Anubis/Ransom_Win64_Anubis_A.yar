
rule Ransom_Win64_Anubis_A{
	meta:
		description = "Ransom:Win64/Anubis.A,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 0a 00 00 "
		
	strings :
		$a_01_0 = {2e 61 6e 75 62 69 73 } //1 .anubis
		$a_01_1 = {52 45 53 54 4f 52 45 20 46 49 4c 45 53 2e 74 78 74 } //1 RESTORE FILES.txt
		$a_01_2 = {2f 4b 45 59 3d } //1 /KEY=
		$a_01_3 = {2f 57 49 50 45 4d 4f 44 45 } //1 /WIPEMODE
		$a_01_4 = {2f 65 6c 65 76 61 74 65 64 } //1 /elevated
		$a_01_5 = {2f 50 46 41 44 3d } //1 /PFAD=
		$a_01_6 = {44 65 6c 65 74 69 6e 67 20 73 65 72 76 69 63 65 73 2e 2e 2e } //1 Deleting services...
		$a_01_7 = {45 6e 63 72 79 70 74 69 6f 6e 20 63 6f 6d 70 6c 65 74 65 64 20 69 6e 3a } //1 Encryption completed in:
		$a_01_8 = {44 69 72 65 63 74 6f 72 79 20 77 61 6c 6b 20 63 6f 6d 70 6c 65 74 65 64 20 77 69 74 68 20 77 61 72 6e 69 6e 67 73 3a 20 25 76 } //1 Directory walk completed with warnings: %v
		$a_01_9 = {3d 3d 3d 20 45 6e 63 72 79 70 74 69 6f 6e 20 53 74 61 74 69 73 74 69 63 73 20 3d 3d 3d } //1 === Encryption Statistics ===
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1) >=6
 
}