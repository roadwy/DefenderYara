
rule Ransom_Win32_Blacksuit_SA_MTB{
	meta:
		description = "Ransom:Win32/Blacksuit.SA!MTB,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {63 00 6d 00 64 00 2e 00 65 00 78 00 65 00 20 00 2f 00 63 00 20 00 76 00 73 00 73 00 61 00 64 00 6d 00 69 00 6e 00 20 00 64 00 65 00 6c 00 65 00 74 00 65 00 20 00 73 00 68 00 61 00 64 00 6f 00 77 00 73 00 20 00 2f 00 61 00 6c 00 6c 00 20 00 2f 00 71 00 75 00 69 00 65 00 74 00 } //1 cmd.exe /c vssadmin delete shadows /all /quiet
		$a_01_1 = {72 00 65 00 61 00 64 00 6d 00 65 00 2e 00 62 00 6c 00 61 00 63 00 6b 00 73 00 75 00 69 00 74 00 2e 00 74 00 78 00 74 00 } //1 readme.blacksuit.txt
		$a_01_2 = {2d 42 45 47 49 4e 20 52 53 41 20 50 55 42 4c 49 43 20 4b 45 59 2d } //1 -BEGIN RSA PUBLIC KEY-
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}