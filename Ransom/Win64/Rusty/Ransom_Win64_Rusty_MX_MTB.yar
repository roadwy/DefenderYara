
rule Ransom_Win64_Rusty_MX_MTB{
	meta:
		description = "Ransom:Win64/Rusty.MX!MTB,SIGNATURE_TYPE_PEHSTR,07 00 07 00 03 00 00 "
		
	strings :
		$a_01_0 = {52 75 73 74 79 20 52 61 6e 73 6f 6d 77 61 72 65 } //5 Rusty Ransomware
		$a_01_1 = {72 61 6e 73 6f 6d 6e 6f 74 65 2e 65 78 65 } //1 ransomnote.exe
		$a_01_2 = {65 6e 63 72 79 70 74 5f 64 61 74 65 2e 74 78 74 } //1 encrypt_date.txt
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=7
 
}