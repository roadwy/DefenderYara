
rule Ransom_Win64_Zudochka_LK_MTB{
	meta:
		description = "Ransom:Win64/Zudochka.LK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_03_0 = {48 ff c6 80 f3 0c 48 8b 85 90 01 02 00 00 88 1c 10 48 ff 85 90 01 02 00 00 48 ff c7 4c 39 f6 73 28 0f b6 1f 48 8b 95 90 01 02 00 00 48 3b 95 90 01 02 00 00 75 ce 90 00 } //3
		$a_01_1 = {48 41 43 4b 45 44 2e 70 6e 67 } //1 HACKED.png
		$a_01_2 = {50 65 6e 74 65 73 74 5c 73 6f 75 72 63 65 5c 72 65 70 6f 73 5c 72 75 73 74 77 61 72 65 5c 72 75 73 74 77 61 72 65 5c 74 61 72 67 65 74 5c 72 65 6c 65 61 73 65 5c 64 65 70 73 5c 72 75 73 74 77 61 72 65 2e 70 64 62 } //1 Pentest\source\repos\rustware\rustware\target\release\deps\rustware.pdb
		$a_01_3 = {2e 72 73 6d } //1 .rsm
	condition:
		((#a_03_0  & 1)*3+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}