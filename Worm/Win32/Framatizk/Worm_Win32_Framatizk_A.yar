
rule Worm_Win32_Framatizk_A{
	meta:
		description = "Worm:Win32/Framatizk.A,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 06 00 00 "
		
	strings :
		$a_01_0 = {46 72 6d 5a 69 74 61 } //1 FrmZita
		$a_01_1 = {54 69 6d 65 72 53 70 72 65 61 64 4d 65 } //1 TimerSpreadMe
		$a_01_2 = {78 00 5c 00 5a 00 69 00 74 00 61 00 2e 00 76 00 62 00 70 00 } //1 x\Zita.vbp
		$a_01_3 = {6f 00 70 00 65 00 6e 00 20 00 66 00 74 00 70 00 2e 00 77 00 65 00 62 00 63 00 69 00 6e 00 64 00 61 00 72 00 69 00 6f 00 2e 00 63 00 6f 00 6d 00 } //1 open ftp.webcindario.com
		$a_01_4 = {6d 00 67 00 65 00 74 00 20 00 62 00 70 00 77 00 64 00 2e 00 7a 00 69 00 70 00 } //1 mget bpwd.zip
		$a_01_5 = {65 00 78 00 65 00 2e 00 72 00 65 00 72 00 6f 00 6c 00 70 00 78 00 45 00 } //1 exe.rerolpxE
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=5
 
}