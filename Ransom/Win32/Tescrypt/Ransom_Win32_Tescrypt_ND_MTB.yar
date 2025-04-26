
rule Ransom_Win32_Tescrypt_ND_MTB{
	meta:
		description = "Ransom:Win32/Tescrypt.ND!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_81_0 = {76 62 64 66 65 74 68 69 37 35 74 79 6a 67 66 63 78 76 67 73 72 65 79 35 34 74 72 64 68 66 } //3 vbdfethi75tyjgfcxvgsrey54trdhf
		$a_81_1 = {63 76 67 66 79 74 69 37 36 69 67 68 6e 67 6a 74 79 69 37 36 6b 79 67 68 62 } //2 cvgfyti76ighngjtyi76kyghb
		$a_81_2 = {73 75 70 70 65 72 53 74 72 } //1 supperStr
	condition:
		((#a_81_0  & 1)*3+(#a_81_1  & 1)*2+(#a_81_2  & 1)*1) >=6
 
}