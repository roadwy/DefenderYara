
rule Ransom_Win32_Cryptolocker_PAK_MTB{
	meta:
		description = "Ransom:Win32/Cryptolocker.PAK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {2f 43 20 6b 69 6c 6c 2e 62 61 74 } //1 /C kill.bat
		$a_01_1 = {69 20 77 69 6c 6c 20 72 65 63 6f 76 65 72 20 79 6f 75 72 20 66 69 6c 65 73 21 } //1 i will recover your files!
		$a_01_2 = {64 32 56 73 62 43 42 30 61 47 6c 7a 49 48 4e 31 59 32 74 7a 4c 43 42 6f 59 53 45 3d } //1 d2VsbCB0aGlzIHN1Y2tzLCBoYSE=
		$a_01_3 = {62 57 39 75 5a 58 6b 73 49 47 31 76 62 6d 56 35 4c 43 42 74 62 32 35 6c 65 53 45 3d } //1 bW9uZXksIG1vbmV5LCBtb25leSE=
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}