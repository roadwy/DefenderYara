
rule TrojanSpy_Win32_Banker_ADH{
	meta:
		description = "TrojanSpy:Win32/Banker.ADH,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 08 00 00 01 00 "
		
	strings :
		$a_01_0 = {4d 73 53 68 75 74 74 5f } //01 00  MsShutt_
		$a_01_1 = {5c 53 6f 66 74 77 61 72 65 5c 41 6c 78 5c 43 6f 6e 66 69 67 5c } //01 00  \Software\Alx\Config\
		$a_01_2 = {4d 2e 40 2e 35 2e 37 2e 33 2e 52 2e 2e 43 2e 40 2e 52 2e 44 } //01 00  M.@.5.7.3.R..C.@.R.D
		$a_01_3 = {53 65 6e 68 61 20 43 61 72 74 61 6f 2e 2e 2e 2e 3a } //01 00  Senha Cartao....:
		$a_01_4 = {48 2e 35 2e 42 2e 43 } //01 00  H.5.B.C
		$a_01_5 = {53 65 72 69 61 6c 20 48 44 2e 2e 2e 2e 3a } //01 00  Serial HD....:
		$a_00_6 = {63 00 72 00 65 00 64 00 69 00 74 00 46 00 6f 00 72 00 6d 00 3a 00 73 00 65 00 63 00 75 00 72 00 69 00 74 00 79 00 43 00 6f 00 64 00 65 00 } //01 00  creditForm:securityCode
		$a_03_7 = {4d 61 71 75 69 6e 61 2e 2e 2e 2e 2e 2e 3a 20 90 02 20 55 73 75 61 72 69 6f 2e 2e 2e 2e 2e 2e 3a 20 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}