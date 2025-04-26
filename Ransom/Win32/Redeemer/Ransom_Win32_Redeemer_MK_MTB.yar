
rule Ransom_Win32_Redeemer_MK_MTB{
	meta:
		description = "Ransom:Win32/Redeemer.MK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_80_0 = {52 65 61 64 20 4d 65 2e 54 58 54 } //Read Me.TXT  1
		$a_80_1 = {41 6c 6c 20 79 6f 75 72 20 66 69 6c 65 73 20 68 61 76 65 20 62 65 65 6e 20 65 6e 63 72 79 70 74 65 64 } //All your files have been encrypted  1
		$a_80_2 = {74 6f 20 64 65 63 72 79 70 74 20 79 6f 75 72 20 66 69 6c 65 73 20 79 6f 75 20 77 69 6c 6c 20 6e 65 65 64 20 74 6f 20 70 61 79 } //to decrypt your files you will need to pay  1
		$a_80_3 = {52 65 64 65 65 6d 65 72 4d 75 74 65 78 } //RedeemerMutex  1
		$a_80_4 = {53 4f 46 54 57 41 52 45 5c 52 65 64 65 65 6d 65 72 } //SOFTWARE\Redeemer  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1) >=4
 
}