
rule Ransom_Win32_Robbinhood_C_dha{
	meta:
		description = "Ransom:Win32/Robbinhood.C!dha,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 03 00 00 "
		
	strings :
		$a_02_0 = {67 6f 2f 73 72 63 2f 4e 65 77 42 6f 73 73 90 0f 01 00 2f 6d 61 69 6e 2e 67 6f } //1
		$a_00_1 = {67 6f 2f 73 72 63 2f 4e 65 77 42 6f 73 73 32 2f 6d 61 69 6e 2e 67 6f } //10 go/src/NewBoss2/main.go
		$a_00_2 = {5f 53 71 75 61 72 65 5c 75 70 5c 77 69 6e 6c 6f 67 6f 6e 2e 65 78 65 } //5 _Square\up\winlogon.exe
	condition:
		((#a_02_0  & 1)*1+(#a_00_1  & 1)*10+(#a_00_2  & 1)*5) >=15
 
}