
rule Trojan_Win32_Guloader_GZN_MTB{
	meta:
		description = "Trojan:Win32/Guloader.GZN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {69 6e 64 6b 6c 61 73 73 65 72 69 6e 67 65 72 5c 50 6a 65 72 72 6f 74 2e 64 6c 6c } //1 indklasseringer\Pjerrot.dll
		$a_01_1 = {46 61 72 69 73 69 73 6d 65 6e 32 34 2e 6f 70 74 } //1 Farisismen24.opt
		$a_01_2 = {73 65 6d 69 72 69 64 64 6c 65 2e 66 6c 67 } //1 semiriddle.flg
		$a_01_3 = {74 65 6b 73 74 69 6c 61 72 62 65 6a 64 65 72 65 6e 73 2e 74 78 74 } //1 tekstilarbejderens.txt
		$a_01_4 = {74 65 67 6e 65 73 79 73 74 65 6d 65 72 5c 73 65 6c 76 6d 6f 72 64 73 62 61 61 64 65 2e 62 61 72 } //1 tegnesystemer\selvmordsbaade.bar
		$a_01_5 = {74 72 61 76 65 73 6b 6f 65 6e 2e 69 6e 69 } //1 traveskoen.ini
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}