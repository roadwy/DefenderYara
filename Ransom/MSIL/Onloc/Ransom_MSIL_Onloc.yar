
rule Ransom_MSIL_Onloc{
	meta:
		description = "Ransom:MSIL/Onloc,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 04 00 00 05 00 "
		
	strings :
		$a_01_0 = {3e 00 3e 00 3e 00 20 00 48 00 61 00 63 00 6b 00 65 00 64 00 20 00 42 00 79 00 20 00 4c 00 6f 00 63 00 6b 00 30 00 6e 00 20 00 52 00 61 00 6e 00 73 00 6f 00 6d 00 77 00 61 00 72 00 65 00 20 00 21 00 20 00 3c 00 3c 00 3c 00 } //05 00  >>> Hacked By Lock0n Ransomware ! <<<
		$a_01_1 = {31 00 45 00 68 00 48 00 61 00 65 00 51 00 35 00 78 00 38 00 51 00 34 00 77 00 46 00 36 00 32 00 51 00 77 00 71 00 52 00 55 00 66 00 6f 00 46 00 72 00 62 00 59 00 6f 00 32 00 50 00 4c 00 52 00 37 00 63 00 } //05 00  1EhHaeQ5x8Q4wF62QwqRUfoFrbYo2PLR7c
		$a_01_2 = {50 72 6f 6a 65 74 73 5c 4c 6f 63 6b 6f 6e 20 52 61 6e 73 6f 6d 77 61 72 65 5c 4c 6f 63 6b 6f 6e 20 52 61 6e 73 6f 6d 77 61 72 65 5c 6f 62 6a 5c 44 65 62 75 67 5c 4c 6f 63 6b 6f 6e 20 52 61 6e 73 6f 6d 77 61 72 65 2e 70 64 62 } //05 00  Projets\Lockon Ransomware\Lockon Ransomware\obj\Debug\Lockon Ransomware.pdb
		$a_01_3 = {4c 00 6f 00 63 00 6b 00 6f 00 6e 00 20 00 52 00 61 00 6e 00 73 00 6f 00 6d 00 77 00 61 00 72 00 65 00 2e 00 65 00 78 00 65 00 } //00 00  Lockon Ransomware.exe
		$a_00_4 = {5d 04 00 00 a3 ac 03 80 5c 36 } //00 00 
	condition:
		any of ($a_*)
 
}