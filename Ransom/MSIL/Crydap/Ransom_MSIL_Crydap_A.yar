
rule Ransom_MSIL_Crydap_A{
	meta:
		description = "Ransom:MSIL/Crydap.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_00_0 = {43 72 79 70 74 6f 77 61 6c 6c 2e 50 72 6f 70 65 72 74 69 65 73 } //1 Cryptowall.Properties
		$a_00_1 = {50 61 64 43 72 79 70 74 2e 70 64 62 } //1 PadCrypt.pdb
		$a_00_2 = {43 72 79 70 74 6f 77 61 6c 6c 5c 62 69 6e 5c 44 65 62 75 67 5c 4f 62 66 75 73 63 61 74 65 64 5c } //1 Cryptowall\bin\Debug\Obfuscated\
		$a_80_3 = {50 61 64 43 72 79 70 74 2e 65 78 65 } //PadCrypt.exe  1
		$a_00_4 = {24 66 61 30 37 38 30 64 33 2d 62 31 34 35 2d 34 32 34 33 2d 38 36 62 39 2d 66 31 63 36 62 37 62 38 61 31 32 30 00 } //1 昤ち㠷搰ⴳㅢ㔴㐭㐲ⴳ㘸㥢昭挱戶户愸㈱0
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_80_3  & 1)*1+(#a_00_4  & 1)*1) >=4
 
}