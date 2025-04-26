
rule Ransom_MSIL_TankixCrypt_PA_MTB{
	meta:
		description = "Ransom:MSIL/TankixCrypt.PA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {2e 00 54 00 41 00 4e 00 4b 00 49 00 58 00 } //1 .TANKIX
		$a_01_1 = {5c 00 52 00 45 00 41 00 44 00 5f 00 4d 00 45 00 2e 00 74 00 78 00 74 00 } //1 \READ_ME.txt
		$a_01_2 = {69 00 6e 00 66 00 65 00 63 00 74 00 65 00 64 00 20 00 62 00 79 00 20 00 54 00 61 00 6e 00 6b 00 69 00 20 00 58 00 20 00 52 00 61 00 6e 00 73 00 6f 00 6d 00 77 00 61 00 72 00 65 00 } //1 infected by Tanki X Ransomware
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}