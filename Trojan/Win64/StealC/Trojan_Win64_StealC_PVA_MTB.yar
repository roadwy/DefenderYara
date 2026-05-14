
rule Trojan_Win64_StealC_PVA_MTB{
	meta:
		description = "Trojan:Win64/StealC.PVA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 03 00 00 "
		
	strings :
		$a_00_0 = {68 74 74 70 3a 2f 2f 6b 61 73 6b 64 6b 77 71 6b 77 71 65 2e 73 70 61 63 65 2f 37 7a 69 70 2e 65 78 65 } //5 http://kaskdkwqkwqe.space/7zip.exe
		$a_01_1 = {c7 44 24 28 05 00 00 00 48 c7 44 24 20 00 00 00 00 41 b9 00 00 00 00 4c 8b 44 24 60 48 8d 15 73 27 00 00 b9 00 00 00 00 ff 15 } //2
		$a_00_2 = {43 3a 5c 55 73 65 72 73 5c 50 75 62 6c 69 63 5c 50 69 63 74 75 72 65 73 5c 62 61 63 6b 75 70 2e 65 78 65 } //1 C:\Users\Public\Pictures\backup.exe
	condition:
		((#a_00_0  & 1)*5+(#a_01_1  & 1)*2+(#a_00_2  & 1)*1) >=8
 
}