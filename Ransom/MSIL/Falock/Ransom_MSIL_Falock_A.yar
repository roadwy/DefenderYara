
rule Ransom_MSIL_Falock_A{
	meta:
		description = "Ransom:MSIL/Falock.A,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {2f 70 61 79 6d 65 6e 74 2e 68 74 6d 6c } //1 /payment.html
		$a_01_1 = {2f 73 74 61 74 2e 68 74 6d 6c } //1 /stat.html
		$a_01_2 = {53 00 48 00 41 00 44 00 4f 00 57 00 5f 00 43 00 4f 00 50 00 59 00 5f 00 44 00 49 00 52 00 53 00 } //1 SHADOW_COPY_DIRS
		$a_01_3 = {43 00 4f 00 44 00 45 00 5f 00 44 00 4f 00 57 00 4e 00 4c 00 4f 00 41 00 44 00 5f 00 44 00 49 00 53 00 41 00 42 00 4c 00 45 00 44 00 } //1 CODE_DOWNLOAD_DISABLED
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}