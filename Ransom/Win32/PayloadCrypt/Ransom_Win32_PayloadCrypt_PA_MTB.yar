
rule Ransom_Win32_PayloadCrypt_PA_MTB{
	meta:
		description = "Ransom:Win32/PayloadCrypt.PA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_01_0 = {5c 00 70 00 61 00 79 00 6c 00 6f 00 61 00 64 00 2e 00 6c 00 6f 00 67 00 } //3 \payload.log
		$a_01_1 = {52 45 43 4f 56 45 52 5f 70 61 79 6c 6f 61 64 2e 74 78 74 } //1 RECOVER_payload.txt
		$a_01_2 = {2f 00 63 00 20 00 76 00 73 00 73 00 61 00 64 00 6d 00 69 00 6e 00 2e 00 65 00 78 00 65 00 20 00 64 00 65 00 6c 00 65 00 74 00 65 00 20 00 73 00 68 00 61 00 64 00 6f 00 77 00 73 00 20 00 2f 00 61 00 6c 00 6c 00 20 00 2f 00 71 00 75 00 69 00 65 00 74 00 } //1 /c vssadmin.exe delete shadows /all /quiet
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=5
 
}