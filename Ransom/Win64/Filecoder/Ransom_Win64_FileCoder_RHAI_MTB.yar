
rule Ransom_Win64_FileCoder_RHAI_MTB{
	meta:
		description = "Ransom:Win64/FileCoder.RHAI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 06 00 00 "
		
	strings :
		$a_03_0 = {50 45 00 00 64 86 0f ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 0b 02 03 00 00 ?? 28 00 00 e4 03 00 00 00 00 00 40 42 07 } //2
		$a_01_1 = {2e 64 6f 63 2e 6f 64 74 2e 73 71 6c 2e 6d 64 62 2e 78 6c 73 2e 6f 64 73 2e 70 70 74 } //3 .doc.odt.sql.mdb.xls.ods.ppt
		$a_01_2 = {63 6f 6f 6b 69 65 75 73 65 72 } //1 cookieuser
		$a_01_3 = {52 65 61 64 4d 65 2e 74 78 74 } //1 ReadMe.txt
		$a_01_4 = {43 42 43 45 6e 63 72 79 70 74 65 72 } //1 CBCEncrypter
		$a_01_5 = {48 65 78 61 4c 6f 63 6b 65 72 56 32 } //2 HexaLockerV2
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*3+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*2) >=10
 
}