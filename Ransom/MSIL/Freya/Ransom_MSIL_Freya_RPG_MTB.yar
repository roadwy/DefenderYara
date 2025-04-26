
rule Ransom_MSIL_Freya_RPG_MTB{
	meta:
		description = "Ransom:MSIL/Freya.RPG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {46 72 65 79 61 20 52 61 6e 73 6f 6d 77 61 72 65 } //1 Freya Ransomware
		$a_01_1 = {52 00 65 00 61 00 64 00 4d 00 65 00 2e 00 74 00 78 00 74 00 } //1 ReadMe.txt
		$a_01_2 = {2e 00 4c 00 65 00 77 00 64 00 } //1 .Lewd
		$a_01_3 = {4b 00 65 00 79 00 2e 00 74 00 78 00 74 00 } //1 Key.txt
		$a_01_4 = {4c 00 65 00 77 00 64 00 44 00 65 00 63 00 72 00 79 00 70 00 74 00 6f 00 72 00 2e 00 65 00 78 00 65 00 } //1 LewdDecryptor.exe
		$a_01_5 = {59 00 6f 00 75 00 72 00 41 00 74 00 74 00 61 00 63 00 6b 00 50 00 61 00 74 00 68 00 2e 00 74 00 78 00 74 00 } //1 YourAttackPath.txt
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}